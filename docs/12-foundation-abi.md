# 12. Foundation M1a C ABI

状態: Normative / implementation contract
対象: Ninlil Runtime `0.1.0` Foundation M1a
Public C ABI: `0.1` (`NINLIL_ABI_VERSION = 0x0001`)

## 1. 目的と優先順位

本章は、Foundation M1aを別の実装者が独自判断なしに実装できるよう、public C ABI、Platform Port ABI、callback、ownership、nullability、error時の出力を固定します。

M1aに限り、00〜10章の概念記述と本章が競合する場合は本章を優先します。後続milestoneの概念を削除するものではなく、M1aで利用可能な部分を狭く固定するものです。

本章のC宣言は規範です。実際の`include/ninlil/*.h`は、field順、型、定数値、function signatureを変更せず転記しなければなりません。

## 2. M1aで固定する判断

- Runtime roleは`CONTROLLER`と`ENDPOINT`だけです。
- SimulatorはRuntime roleではなく、複数Runtime、virtual clock、simulated bearer、fault hookを駆動する外部harnessです。
- Application familyは`DESIRED_STATE_COMMAND`と`EVENT_FACT`だけです。
- Submissionはconcrete target配列だけを受け取ります。selectorはM1a非対応です。
- `ADMITTED_SCHEDULED`、counter-offer、supersede、replace、fragmentはM1a非対応です。
- M1aでadmitされたSubmissionは`ADMITTED_READY`だけです。
- Application storageとNinlil storageを同一transactionへ参加させるAPIはM1aにありません。
- Command effectはidempotent absolute apply、またはapplication自身のpersistent dedup/reconcileを必須にします。
- Event consumerはevent IDによるpersistent dedup/reconcileを必須にします。
- EventFactはdeadlineを持ちません。`NINLIL_NO_DEADLINE`を指定します。
- EventFactの1 retry cycleは`NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE` attemptsです。枯渇時はnon-terminal `PARKED_RETRY`となり、eventとcustodyを保持します。
- fresh Bearer availability epochかつ`available=1`、または明示`ninlil_event_resume()`で次cycleを開始します。
- EventFactを未達のまま捨てるには、監査付き`ninlil_event_discard()`が必要です。audit recordのFULL commit後だけspoolを解放します。

## 3. C ABI共通規則

### 3.1 Headerとprimitive

```c
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ABI_VERSION              ((uint16_t)0x0001u)
#define NINLIL_STORAGE_SCHEMA_M1A        ((uint32_t)1u)
#define NINLIL_NO_DEADLINE               UINT64_MAX
#define NINLIL_ID_BYTES                  ((uint32_t)16u)
#define NINLIL_SHA256_BYTES              ((uint32_t)32u)
#define NINLIL_MAX_IDEMPOTENCY_BYTES     ((uint32_t)64u)
#define NINLIL_MAX_EVIDENCE_BYTES        ((uint32_t)128u)
#define NINLIL_MAX_AUDIT_METADATA_BYTES  ((uint32_t)128u)
#define NINLIL_MAX_TEXT_ID_BYTES         ((uint32_t)63u)
#define NINLIL_M1A_MAX_STORAGE_VALUE_BYTES ((uint32_t)65536u)
#define NINLIL_DIGEST_SHA256             ((uint16_t)1u)
#define NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE ((uint32_t)8u)
#define NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS ((uint32_t)4u)
#define NINLIL_M1A_MAX_RETRY_DELAY_MS      ((uint64_t)600000u)
#define NINLIL_M1A_MAX_ATTEMPT_RECEIPT_TIMEOUT_MS ((uint64_t)600000u)
#define NINLIL_M1A_MAX_RETRY_BACKOFF_MS    ((uint64_t)60000u)
#define NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS ((uint64_t)60000u)
#define NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS ((uint32_t)8u)
#define NINLIL_M1A_EVENT_RESUME_OPERATION_SLOT_BYTES ((uint64_t)256u)
#define NINLIL_M1A_EVENT_DISCARD_OPERATION_SLOT_BYTES ((uint64_t)512u)
#define NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES ((uint64_t)2560u)
#define NINLIL_M1A_MAX_RETENTION_MS          ((uint64_t)604800000u)

#define NINLIL_STRUCT_HEADER \
    uint16_t abi_version;   \
    uint16_t struct_size

typedef int32_t  ninlil_status_t;
typedef uint32_t ninlil_role_t;
typedef uint32_t ninlil_environment_t;
typedef uint32_t ninlil_family_t;
typedef uint32_t ninlil_direction_t;
typedef uint32_t ninlil_admission_authority_t;
typedef uint32_t ninlil_apply_contract_t;
typedef uint32_t ninlil_custody_policy_t;
typedef uint32_t ninlil_evidence_stage_t;
typedef uint32_t ninlil_submission_kind_t;
typedef uint32_t ninlil_retry_guidance_t;
typedef uint32_t ninlil_reason_t;
typedef uint32_t ninlil_disposition_t;
typedef uint32_t ninlil_effect_certainty_t;
typedef uint32_t ninlil_application_result_kind_t;
typedef uint32_t ninlil_callback_action_t;
typedef uint32_t ninlil_reconcile_action_t;
typedef uint32_t ninlil_transaction_state_t;
typedef uint32_t ninlil_outcome_t;
typedef uint32_t ninlil_deadline_verdict_t;
typedef uint32_t ninlil_cancel_kind_t;
typedef uint32_t ninlil_runtime_health_t;
typedef uint32_t ninlil_resource_kind_t;
typedef uint32_t ninlil_clock_trust_t;
typedef uint32_t ninlil_storage_status_t;
typedef uint32_t ninlil_storage_mode_t;
typedef uint32_t ninlil_durability_t;
typedef uint32_t ninlil_bearer_status_t;
typedef uint32_t ninlil_bearer_message_kind_t;
typedef uint32_t ninlil_bearer_send_kind_t;
typedef uint32_t ninlil_tx_gate_status_t;
typedef uint32_t ninlil_port_status_t;
typedef uint32_t ninlil_origin_auth_status_t;
typedef uint32_t ninlil_assurance_profile_t;
typedef uint32_t ninlil_event_resume_kind_t;
typedef uint32_t ninlil_event_discard_kind_t;
typedef uint32_t ninlil_event_resume_reason_t;
typedef uint32_t ninlil_event_discard_reason_t;
typedef uint32_t ninlil_event_park_cause_t;
```

Public ABIではC `enum`を使いません。C compilerごとのenum size差を避けるため、固定幅typedefと以下の定数を使用します。

`NINLIL_STRUCT_HEADER`を持つstructだけがsize-negotiated ABI structです。次の固定value/view typeは例外で、layoutが型の全契約です。

```c
typedef struct ninlil_id128 {
    uint8_t bytes[16];
} ninlil_id128_t;

typedef struct ninlil_digest256 {
    uint16_t algorithm;
    uint16_t reserved_zero;
    uint8_t bytes[32];
} ninlil_digest256_t;

typedef struct ninlil_bytes_view {
    const uint8_t *data;
    uint32_t length;
} ninlil_bytes_view_t;

typedef struct ninlil_mut_bytes {
    uint8_t *data;
    uint32_t capacity;
    uint32_t length;
} ninlil_mut_bytes_t;

typedef struct ninlil_text_id {
    uint8_t length;
    uint8_t bytes[63];
} ninlil_text_id_t;

#define NINLIL_LOCAL_IDENTITY_HAS_DEVICE       ((uint32_t)1u << 0)
#define NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION ((uint32_t)1u << 1)
#define NINLIL_LOCAL_IDENTITY_HAS_SITE         ((uint32_t)1u << 2)

typedef struct ninlil_local_identity {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t device_id;
    ninlil_id128_t installation_id;
    ninlil_id128_t site_domain_id;
    uint64_t binding_epoch;
    uint64_t membership_epoch;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_local_identity_t;
```

規則:

- `ninlil_id128_t`のall-zeroは「未指定」です。required IDでall-zeroを渡すと`NINLIL_E_INVALID_ARGUMENT`です。
- required `ninlil_digest256_t`は`algorithm == NINLIL_DIGEST_SHA256`、`reserved_zero == 0`です。fieldがkind規則でunused/absentの場合だけalgorithm/reserved/32 bytesをすべてzeroにします。他のalgorithm値やpartial-zero absenceはinvalidです。
- `reserved_zero`は0必須です。
- `bytes_view.length == 0`なら`data`はNULLでなければなりません。
- `bytes_view.length > 0`なら`data`はnon-NULLです。
- `mut_bytes.capacity == 0`なら`data`はNULLです。
- `mut_bytes.capacity > 0`なら`data`はnon-NULLです。Storage `get` / `iter_next` call前は`length == 0` requiredで、lengthをinput data sizeとして解釈しません。
- `ninlil_text_id_t`はcopyable inline valueです。lengthは1〜63、`bytes[0..length)`だけがtext、残りはzero、NUL終端しません。
- Descriptor inputのtext ID viewも長さ1〜63 byteのASCIIです。Runtimeは登録成功前に`ninlil_text_id_t`へcopyします。
- namespaceは`[a-z0-9][a-z0-9.-]*`、service/schema IDは`[a-z0-9][a-z0-9._-]*`です。
- local identityのflags、ID、epochはconcrete targetと同じpresence規則です。Foundation TEST fixtureではdeviceとsiteをrequired、installationをoptionalとします。
- local identity snapshotは1 Runtime lifetime中immutableです。M1aでattachment/membershipが変わる場合はRuntimeをdestroy/recreateし、pending recordはadmission時にpersistした旧snapshotを維持します。M4では同じboundaryの供給元をreal identity/attachment backendへ置換します。

### 3.2 API status

```c
#define NINLIL_OK                         ((ninlil_status_t)0)
#define NINLIL_E_INVALID_ARGUMENT         ((ninlil_status_t)1)
#define NINLIL_E_ABI_MISMATCH             ((ninlil_status_t)2)
#define NINLIL_E_UNSUPPORTED              ((ninlil_status_t)3)
#define NINLIL_E_WRONG_THREAD             ((ninlil_status_t)4)
#define NINLIL_E_REENTRANT                 ((ninlil_status_t)5)
#define NINLIL_E_BUFFER_TOO_SMALL          ((ninlil_status_t)6)
#define NINLIL_E_NOT_FOUND                 ((ninlil_status_t)7)
#define NINLIL_E_CONFLICT                  ((ninlil_status_t)8)
#define NINLIL_E_CAPACITY_EXHAUSTED        ((ninlil_status_t)9)
#define NINLIL_E_STORAGE                   ((ninlil_status_t)10)
#define NINLIL_E_STORAGE_CORRUPT           ((ninlil_status_t)11)
#define NINLIL_E_STORAGE_COMMIT_UNKNOWN    ((ninlil_status_t)12)
#define NINLIL_E_CLOCK_UNCERTAIN           ((ninlil_status_t)13)
#define NINLIL_E_ENTROPY                   ((ninlil_status_t)14)
#define NINLIL_E_WOULD_BLOCK               ((ninlil_status_t)15)
#define NINLIL_E_INVALID_STATE             ((ninlil_status_t)16)
#define NINLIL_E_CALLBACK                  ((ninlil_status_t)17) /* M1a reserved; never generated */
#define NINLIL_E_DEGRADED                  ((ninlil_status_t)18)
#define NINLIL_E_INTERNAL                  ((ninlil_status_t)19) /* M1a reserved; never generated */
```

API invocation errorとSubmission rejectionを混同しません。構文的に有効なSubmissionがpolicy/capacityで拒否された場合、`ninlil_submit()`自体は`NINLIL_OK`を返し、`out_result.kind = NINLIL_SUBMISSION_REJECTED`とします。

`NINLIL_E_CALLBACK`と`NINLIL_E_INTERNAL`はABI value予約だけで、M1a Coreはpublic APIから生成しません。Callback FATAL/contract violationは7.2のdurable recovery、Runtime `DEGRADED` health/reasonへ写像し、呼出中のrecoverable internal invariant/Port failureは規定済みの`NINLIL_E_DEGRADED`、storage、clock、capacity等のspecific statusへ写像します。Reserved statusをcatch-allにしません。

### 3.3 ABI struct validation

- Input structは`abi_version == NINLIL_ABI_VERSION`必須です。
- `struct_size`がM1aのrequired末尾fieldより小さい場合は`NINLIL_E_ABI_MISMATCH`です。
- `struct_size`がlibraryの既知sizeより大きい場合、未知tailを読みません。
- `reserved_zero`、reserved flag、registryに存在しないunknown numeric enum値の入力は`NINLIL_E_INVALID_ARGUMENT`です。名前付き`*_RESERVED`値はknownですがM1aで実行不能なので、各APIの§14規則どおり`NINLIL_E_UNSUPPORTED`です。Unknown numeric値をUNSUPPORTEDへ丸めません。
- Output structはcallerがABI header、buffer pointer、capacityだけを初期化し、それ以外を0にします。
- Libraryはcallerの`struct_size`を超えて書きません。

## 4. M1a enum domain

### 4.1 Role、environment、family

```c
#define NINLIL_ROLE_CONTROLLER             ((ninlil_role_t)1u)
#define NINLIL_ROLE_ENDPOINT               ((ninlil_role_t)2u)
#define NINLIL_ROLE_CELL_AGENT_RESERVED    ((ninlil_role_t)3u)

#define NINLIL_ENV_TEST                    ((ninlil_environment_t)1u)
#define NINLIL_ENV_LAB_RESERVED            ((ninlil_environment_t)2u)
#define NINLIL_ENV_FIELD_RESERVED          ((ninlil_environment_t)3u)
#define NINLIL_ENV_PRODUCTION_RESERVED     ((ninlil_environment_t)4u)

#define NINLIL_FAMILY_EVENT_FACT           ((ninlil_family_t)1u)
#define NINLIL_FAMILY_DESIRED_STATE        ((ninlil_family_t)2u)
#define NINLIL_FAMILY_LATEST_STATE_RESERVED ((ninlil_family_t)3u)
#define NINLIL_FAMILY_MEASUREMENT_RESERVED  ((ninlil_family_t)4u)
#define NINLIL_FAMILY_TRANSFER_RESERVED     ((ninlil_family_t)5u)
#define NINLIL_FAMILY_CONFIG_RESERVED       ((ninlil_family_t)6u)
#define NINLIL_FAMILY_NETWORK_CONTROL_RESERVED ((ninlil_family_t)0x80000001u)
#define NINLIL_FAMILY_MASK_EVENT_FACT      ((uint32_t)1u << 0)
#define NINLIL_FAMILY_MASK_DESIRED_STATE   ((uint32_t)1u << 1)
```

`CELL_AGENT_RESERVED`、`LAB_RESERVED`以降、reserved familyの使用はM1aで`NINLIL_E_UNSUPPORTED`です。`SIMULATOR` role値は存在しません。

### 4.2 Service contract

```c
#define NINLIL_DIRECTION_UPLINK             ((ninlil_direction_t)1u)
#define NINLIL_DIRECTION_DOWNLINK           ((ninlil_direction_t)2u)
#define NINLIL_DIRECTION_BIDIRECTIONAL_RESERVED ((ninlil_direction_t)3u)

#define NINLIL_AUTHORITY_CONTROLLER_ONLY    ((ninlil_admission_authority_t)1u)
#define NINLIL_AUTHORITY_ORIGIN_WITH_GRANT  ((ninlil_admission_authority_t)2u)

#define NINLIL_APPLY_IDEMPOTENT             ((ninlil_apply_contract_t)1u)
#define NINLIL_APPLY_APPLICATION_DEDUP       ((ninlil_apply_contract_t)2u)
#define NINLIL_APPLY_ATOMIC_PARTICIPANT_RESERVED ((ninlil_apply_contract_t)3u)

#define NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE ((ninlil_custody_policy_t)1u)
#define NINLIL_CUSTODY_RELEASE_ON_TRANSPORT_RESERVED ((ninlil_custody_policy_t)2u)
```

M1a validation:

- EventFactは`UPLINK + ORIGIN_WITH_GRANT + APPLY_APPLICATION_DEDUP`です。
- DesiredStateCommandは`DOWNLINK + CONTROLLER_ONLY`で、apply contractは`IDEMPOTENT`または`APPLICATION_DEDUP`です。
- custody policyは`UNTIL_REQUIRED_EVIDENCE`だけです。

### 4.3 Evidence、result、state

```c
#define NINLIL_EVIDENCE_NONE                ((ninlil_evidence_stage_t)0u)
#define NINLIL_EVIDENCE_RECEIVED            ((ninlil_evidence_stage_t)1u)
#define NINLIL_EVIDENCE_DURABLY_RECORDED    ((ninlil_evidence_stage_t)2u)
#define NINLIL_EVIDENCE_APPLIED             ((ninlil_evidence_stage_t)3u)
#define NINLIL_EVIDENCE_VERIFIED            ((ninlil_evidence_stage_t)4u)

#define NINLIL_EVIDENCE_MASK(stage)         ((uint32_t)1u << (stage))

#define NINLIL_SUBMISSION_INVALID           ((ninlil_submission_kind_t)0u)
#define NINLIL_SUBMISSION_ADMITTED_READY    ((ninlil_submission_kind_t)1u)
#define NINLIL_SUBMISSION_ALREADY_ADMITTED  ((ninlil_submission_kind_t)2u)
#define NINLIL_SUBMISSION_REJECTED          ((ninlil_submission_kind_t)3u)
#define NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT ((ninlil_submission_kind_t)4u)
#define NINLIL_SUBMISSION_ADMITTED_SCHEDULED_RESERVED ((ninlil_submission_kind_t)5u)
#define NINLIL_SUBMISSION_COUNTER_OFFERED_RESERVED ((ninlil_submission_kind_t)6u)

#define NINLIL_RETRY_NEVER                  ((ninlil_retry_guidance_t)0u)
#define NINLIL_RETRY_SAME_AFTER             ((ninlil_retry_guidance_t)1u)
#define NINLIL_RETRY_MODIFIED               ((ninlil_retry_guidance_t)2u)
#define NINLIL_RETRY_OPERATOR_ACTION        ((ninlil_retry_guidance_t)3u)

#define NINLIL_DISPOSITION_NONE             ((ninlil_disposition_t)0u)
#define NINLIL_DISPOSITION_RETRY_LATER      ((ninlil_disposition_t)1u)
#define NINLIL_DISPOSITION_INVALID_PAYLOAD  ((ninlil_disposition_t)2u)
#define NINLIL_DISPOSITION_UNSUPPORTED_SCHEMA ((ninlil_disposition_t)3u)
#define NINLIL_DISPOSITION_UNAUTHORIZED_SERVICE ((ninlil_disposition_t)4u)
#define NINLIL_DISPOSITION_STALE_NOT_APPLIED ((ninlil_disposition_t)5u)
#define NINLIL_DISPOSITION_APPLICATION_BUSY ((ninlil_disposition_t)6u)
#define NINLIL_DISPOSITION_APPLY_FAILED     ((ninlil_disposition_t)7u)
#define NINLIL_DISPOSITION_VERIFY_FAILED    ((ninlil_disposition_t)8u)
#define NINLIL_DISPOSITION_CAPACITY_EXHAUSTED ((ninlil_disposition_t)9u)
#define NINLIL_DISPOSITION_OUTCOME_UNKNOWN  ((ninlil_disposition_t)10u)

#define NINLIL_EFFECT_CERTAINTY_NONE          ((ninlil_effect_certainty_t)0u)
#define NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN ((ninlil_effect_certainty_t)1u)
#define NINLIL_EFFECT_CERTAINTY_POSSIBLE      ((ninlil_effect_certainty_t)2u)

#define NINLIL_APP_RESULT_POSITIVE_EVIDENCE ((ninlil_application_result_kind_t)1u)
#define NINLIL_APP_RESULT_DISPOSITION       ((ninlil_application_result_kind_t)2u)

#define NINLIL_CALLBACK_COMPLETE            ((ninlil_callback_action_t)1u)
#define NINLIL_CALLBACK_DEFER               ((ninlil_callback_action_t)2u)
#define NINLIL_CALLBACK_FATAL               ((ninlil_callback_action_t)3u)

#define NINLIL_RECONCILE_REDELIVER          ((ninlil_reconcile_action_t)1u)
#define NINLIL_RECONCILE_KNOWN_RESULT       ((ninlil_reconcile_action_t)2u)
#define NINLIL_RECONCILE_RETRY_LATER        ((ninlil_reconcile_action_t)3u)
#define NINLIL_RECONCILE_OUTCOME_UNKNOWN    ((ninlil_reconcile_action_t)4u)

#define NINLIL_TXN_READY                    ((ninlil_transaction_state_t)1u)
#define NINLIL_TXN_DISPATCHING              ((ninlil_transaction_state_t)2u)
#define NINLIL_TXN_AWAITING_EVIDENCE        ((ninlil_transaction_state_t)3u)
#define NINLIL_TXN_PARKED_RETRY             ((ninlil_transaction_state_t)4u)
#define NINLIL_TXN_TERMINAL                 ((ninlil_transaction_state_t)5u)
#define NINLIL_TXN_WAITING_WINDOW           ((ninlil_transaction_state_t)6u)

#define NINLIL_OUTCOME_NONE                 ((ninlil_outcome_t)0u)
#define NINLIL_OUTCOME_SATISFIED            ((ninlil_outcome_t)1u)
#define NINLIL_OUTCOME_EXPIRED              ((ninlil_outcome_t)2u)
#define NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT ((ninlil_outcome_t)3u)
#define NINLIL_OUTCOME_FAILED_DEFINITIVE    ((ninlil_outcome_t)4u)
#define NINLIL_OUTCOME_UNKNOWN              ((ninlil_outcome_t)5u)
#define NINLIL_OUTCOME_SUPERSEDED_RESERVED  ((ninlil_outcome_t)6u)

#define NINLIL_DEADLINE_PENDING             ((ninlil_deadline_verdict_t)0u)
#define NINLIL_DEADLINE_MET                 ((ninlil_deadline_verdict_t)1u)
#define NINLIL_DEADLINE_MISSED              ((ninlil_deadline_verdict_t)2u)
#define NINLIL_DEADLINE_INDETERMINATE       ((ninlil_deadline_verdict_t)3u)
#define NINLIL_DEADLINE_NOT_APPLICABLE      ((ninlil_deadline_verdict_t)4u)

#define NINLIL_EVENT_PARK_CAUSE_NONE         ((ninlil_event_park_cause_t)0u)
#define NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT ((ninlil_event_park_cause_t)1u)
#define NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE ((ninlil_event_park_cause_t)2u)
#define NINLIL_EVENT_PARK_CAUSE_CAPACITY_UNAVAILABLE ((ninlil_event_park_cause_t)3u)
#define NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATION ((ninlil_event_park_cause_t)4u)
#define NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTED ((ninlil_event_park_cause_t)5u)
```

EventFactはterminal Receiptまたはexplicit discardまで`OUTCOME_NONE`です。retry-cycle枯渇はfailure/expiryではなく`PARKED_RETRY`です。

### 4.4 Reason code

```c
#define NINLIL_REASON_NONE                  ((ninlil_reason_t)0u)

/* M1a admission/validation: 1..63 */
#define NINLIL_REASON_UNSUPPORTED_FAMILY    ((ninlil_reason_t)1u)
#define NINLIL_REASON_UNSUPPORTED_SELECTOR  ((ninlil_reason_t)2u)
#define NINLIL_REASON_TARGET_COUNT_UNSUPPORTED ((ninlil_reason_t)3u)
#define NINLIL_REASON_INVALID_SCHEMA        ((ninlil_reason_t)4u)
#define NINLIL_REASON_INVALID_PAYLOAD_LENGTH ((ninlil_reason_t)5u)
#define NINLIL_REASON_INVALID_CONTENT_DIGEST ((ninlil_reason_t)6u)
#define NINLIL_REASON_DEADLINE_INVALID      ((ninlil_reason_t)7u)
#define NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED ((ninlil_reason_t)8u)
#define NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID ((ninlil_reason_t)9u)
#define NINLIL_REASON_EVIDENCE_UNSUPPORTED  ((ninlil_reason_t)10u)
#define NINLIL_REASON_CAPACITY_EXHAUSTED    ((ninlil_reason_t)11u)
#define NINLIL_REASON_MODIFICATION_REQUIRED ((ninlil_reason_t)12u)
#define NINLIL_REASON_IDEMPOTENCY_CONFLICT  ((ninlil_reason_t)13u)
#define NINLIL_REASON_GRANT_INVALID         ((ninlil_reason_t)14u)
#define NINLIL_REASON_GRANT_EXPIRED         ((ninlil_reason_t)15u)
#define NINLIL_REASON_GRANT_LIMIT_EXCEEDED  ((ninlil_reason_t)16u)
#define NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE ((ninlil_reason_t)17u)
#define NINLIL_REASON_STORAGE_IO            ((ninlil_reason_t)18u)
#define NINLIL_REASON_STORAGE_COMMIT_UNKNOWN ((ninlil_reason_t)19u)
#define NINLIL_REASON_CLOCK_UNCERTAIN       ((ninlil_reason_t)20u)
#define NINLIL_REASON_RATE_EXHAUSTED        ((ninlil_reason_t)21u)
#define NINLIL_REASON_TARGET_UNAUTHORIZED   ((ninlil_reason_t)22u)
#define NINLIL_REASON_CALLBACK_CONTRACT     ((ninlil_reason_t)23u)
#define NINLIL_REASON_UNSUPPORTED_DIRECTION ((ninlil_reason_t)24u)

/* M1a outcome/operation: 64..127 */
#define NINLIL_REASON_REQUIRED_EVIDENCE_MET ((ninlil_reason_t)64u)
#define NINLIL_REASON_REQUIRED_EVIDENCE_LATE ((ninlil_reason_t)65u)
#define NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH ((ninlil_reason_t)66u)
/* 67 is reserved. M1a Submission has no caller not-before semantic. */
#define NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING ((ninlil_reason_t)68u)
#define NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING ((ninlil_reason_t)69u)
#define NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT ((ninlil_reason_t)70u)
#define NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED ((ninlil_reason_t)71u)
#define NINLIL_REASON_EVENT_RECEIPT_TIMEOUT ((ninlil_reason_t)72u)
#define NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT ((ninlil_reason_t)73u)
#define NINLIL_REASON_BEARER_UNAVAILABLE    ((ninlil_reason_t)74u)
#define NINLIL_REASON_CAPACITY_UNAVAILABLE  ((ninlil_reason_t)75u)
#define NINLIL_REASON_COUNTER_EXHAUSTED     ((ninlil_reason_t)76u)
#define NINLIL_REASON_STALE_AVAILABILITY_EPOCH ((ninlil_reason_t)77u)
#define NINLIL_REASON_RESUME_CONFLICT       ((ninlil_reason_t)78u)
#define NINLIL_REASON_STALE_SPOOL_REVISION  ((ninlil_reason_t)79u)
#define NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT ((ninlil_reason_t)80u)
#define NINLIL_REASON_DISCARD_CONFLICT      ((ninlil_reason_t)81u)
#define NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH ((ninlil_reason_t)82u)
#define NINLIL_REASON_CANCEL_AFTER_EFFECT_POSSIBLE ((ninlil_reason_t)83u)
#define NINLIL_REASON_EVENT_FACT_IMMUTABLE  ((ninlil_reason_t)84u)
#define NINLIL_REASON_TRANSPORT_RETRY       ((ninlil_reason_t)85u)
#define NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE ((ninlil_reason_t)86u)

/* M1a delivery/application: 128..255. Disposition itself is authoritative. */
#define NINLIL_REASON_APPLICATION_FAILED    ((ninlil_reason_t)128u)
#define NINLIL_REASON_OUTCOME_UNKNOWN       ((ninlil_reason_t)129u)
#define NINLIL_REASON_RECEIVER_UNAVAILABLE  ((ninlil_reason_t)130u)
#define NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT ((ninlil_reason_t)131u)
#define NINLIL_REASON_RECONCILE_RETRY_LATER ((ninlil_reason_t)132u)

/* M1b forward-only reservation: 4096.. */
#define NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION ((ninlil_reason_t)4096u)
#define NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT ((ninlil_reason_t)4097u)
```

この表だけがM1a public reasonの数値registryです。13章のreducerは上記のexact symbolを使用し、別名や独自番号を定義してはなりません。`INVALID_PAYLOAD`、`UNSUPPORTED_SCHEMA`、`UNAUTHORIZED_SERVICE`、`STALE_NOT_APPLIED`、`APPLICATION_BUSY`、`APPLY_FAILED`、`VERIFY_FAILED`は`ninlil_disposition_t`の値が正本であり、同名reasonを重複定義しません。terminal snapshotへ追加の原因分類が必要な場合だけ、`APPLICATION_FAILED`、`CAPACITY_EXHAUSTED`、`TARGET_UNAUTHORIZED`など上記reasonへ写像します。

[foundation-m1a-reason-codes.yaml](../schemas/foundation-m1a-reason-codes.yaml)はtooling用の機械可読mirrorです。symbol/valueの規範は本節だけで、CIは両者の集合・値・重複・reserved value 67をexact比較します。YAMLだけで番号を変更してはなりません。

次の9 symbolは数値ABI/default-guidance metadataを予約しますが、M1a public outputでは**generated 0**です。YAML top-level `m1a_public_generated_zero`がこのexact setをmirrorし、Core、Port、provider、application fixtureはSubmission result、transaction/target snapshot、step health reason、management resultへ生成しません。

- `NINLIL_REASON_UNSUPPORTED_FAMILY`
- `NINLIL_REASON_UNSUPPORTED_SELECTOR`
- `NINLIL_REASON_INVALID_CONTENT_DIGEST`
- `NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID`
- `NINLIL_REASON_MODIFICATION_REQUIRED`
- `NINLIL_REASON_EVENT_RECEIPT_TIMEOUT`
- `NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT`
- `NINLIL_REASON_BEARER_UNAVAILABLE`
- `NINLIL_REASON_CAPACITY_UNAVAILABLE`

理由はclosedです。Family/named reservedはservice registration API `UNSUPPORTED`、selectorはABIで表現不能、content digest mismatchはAPI `INVALID_ARGUMENT`、attempt timeout descriptor不正はservice registration `INVALID_ARGUMENT`です。M1aにcounter-offer/modification-required guardはありません。Origin provider temporary failureはAPI `WOULD_BLOCK`、permanent/invalid responseはAPI `DEGRADED + SUBMISSION_INVALID/reason NONE`ですが、後者はRuntime healthの`GRANT_PROVIDER_UNAVAILABLE`としてreachableなのでzero setへ含めません。Event attempt timeout/park詳細はattempt observationと`event_park_cause`に保持し、public PARKED reasonは常に`EVENT_RETRY_CYCLE_PARKED`です。将来zero-set symbolを生成可能にする変更はmilestone/ABI更新とYAML setからの削除を同じ変更で行います。

Operator/UIがSubmission retry guidanceを明示されなかった場合に使うdefault guidance groupも本節が正本です。YAMLの`default_retry_guidance`は次のgroup membershipをexact mirrorし、CIは全54 symbolがexactly 1 groupへ属することを検査します。

- `NINLIL_RETRY_MODIFIED`: `NINLIL_REASON_UNSUPPORTED_FAMILY`, `NINLIL_REASON_UNSUPPORTED_SELECTOR`, `NINLIL_REASON_TARGET_COUNT_UNSUPPORTED`, `NINLIL_REASON_INVALID_SCHEMA`, `NINLIL_REASON_INVALID_PAYLOAD_LENGTH`, `NINLIL_REASON_INVALID_CONTENT_DIGEST`, `NINLIL_REASON_DEADLINE_INVALID`, `NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED`, `NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID`, `NINLIL_REASON_EVIDENCE_UNSUPPORTED`, `NINLIL_REASON_MODIFICATION_REQUIRED`, `NINLIL_REASON_IDEMPOTENCY_CONFLICT`, `NINLIL_REASON_TARGET_UNAUTHORIZED`, `NINLIL_REASON_UNSUPPORTED_DIRECTION`, `NINLIL_REASON_RESUME_CONFLICT`, `NINLIL_REASON_STALE_SPOOL_REVISION`, `NINLIL_REASON_DISCARD_CONFLICT`
- `NINLIL_RETRY_NEVER`: `NINLIL_REASON_NONE`, `NINLIL_REASON_REQUIRED_EVIDENCE_MET`, `NINLIL_REASON_REQUIRED_EVIDENCE_LATE`, `NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH`, `NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT`, `NINLIL_REASON_STALE_AVAILABILITY_EPOCH`, `NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT`, `NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH`, `NINLIL_REASON_EVENT_FACT_IMMUTABLE`, `NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION`, `NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT`
- `NINLIL_RETRY_OPERATOR_ACTION`: `NINLIL_REASON_GRANT_INVALID`, `NINLIL_REASON_GRANT_EXPIRED`, `NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE`, `NINLIL_REASON_STORAGE_IO`, `NINLIL_REASON_CLOCK_UNCERTAIN`, `NINLIL_REASON_CALLBACK_CONTRACT`, `NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING`, `NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED`, `NINLIL_REASON_COUNTER_EXHAUSTED`, `NINLIL_REASON_CANCEL_AFTER_EFFECT_POSSIBLE`, `NINLIL_REASON_APPLICATION_FAILED`, `NINLIL_REASON_OUTCOME_UNKNOWN`
- `NINLIL_RETRY_SAME_AFTER`: `NINLIL_REASON_CAPACITY_EXHAUSTED`, `NINLIL_REASON_GRANT_LIMIT_EXCEEDED`, `NINLIL_REASON_STORAGE_COMMIT_UNKNOWN`, `NINLIL_REASON_RATE_EXHAUSTED`, `NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING`, `NINLIL_REASON_EVENT_RECEIPT_TIMEOUT`, `NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT`, `NINLIL_REASON_BEARER_UNAVAILABLE`, `NINLIL_REASON_CAPACITY_UNAVAILABLE`, `NINLIL_REASON_TRANSPORT_RETRY`, `NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE`, `NINLIL_REASON_RECEIVER_UNAVAILABLE`, `NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT`, `NINLIL_REASON_RECONCILE_RETRY_LATER`

## 5. Platform Port ABI

### 5.1 Opaque Port handle

```c
typedef void *ninlil_storage_handle_t;
typedef void *ninlil_storage_txn_t;
typedef void *ninlil_storage_iter_t;
typedef void *ninlil_bearer_handle_t;

typedef struct ninlil_runtime ninlil_runtime_t;
typedef struct ninlil_service ninlil_service_t;

typedef struct ninlil_delivery_token {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t context_id;
    uint64_t generation;
    ninlil_id128_t clock_epoch_id;
    uint64_t expires_at_ms;
} ninlil_delivery_token_t;
```

Port handleの実体をCoreは解釈しません。NULLはinvalid handleです。

### 5.2 Allocator、execution、clock、entropy

```c
typedef struct ninlil_allocator_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    void *(*allocate)(void *user, uint64_t size, uint32_t alignment);
    void (*deallocate)(void *user, void *ptr, uint64_t size, uint32_t alignment);
} ninlil_allocator_ops_t;

typedef struct ninlil_execution_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    uint64_t (*current_context_id)(void *user);
} ninlil_execution_ops_t;

#define NINLIL_CLOCK_TRUSTED               ((ninlil_clock_trust_t)1u)
#define NINLIL_CLOCK_UNCERTAIN             ((ninlil_clock_trust_t)2u)

#define NINLIL_PORT_OK                     ((ninlil_port_status_t)0u)
#define NINLIL_PORT_TEMPORARY_FAILURE      ((ninlil_port_status_t)1u)
#define NINLIL_PORT_PERMANENT_FAILURE      ((ninlil_port_status_t)2u)

typedef struct ninlil_time_sample {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t clock_epoch_id;
    uint64_t now_ms;
    ninlil_clock_trust_t trust;
    uint32_t reserved_zero;
} ninlil_time_sample_t;

typedef struct ninlil_clock_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_port_status_t (*now)(void *user, ninlil_time_sample_t *out_sample);
} ninlil_clock_ops_t;

typedef struct ninlil_entropy_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_port_status_t (*fill)(void *user, uint8_t *out, uint32_t length);
} ninlil_entropy_ops_t;
```

規則:

- `allocate`はsize 1以上、alignmentは2の冪で呼ばれます。失敗はNULLです。
- `deallocate`はCoreが以前受け取った同じptr/size/alignmentで1回だけ呼びます。
- `current_context_id`はnon-zeroで、同一execution context中は同値です。値の意味は比較以外に使用しません。
- Runtime create時のcontext IDをownerとして固定します。
- Clockの`now_ms`は同じ`clock_epoch_id`内で減少してはいけません。
- Runtime再作成後も継続するtimelineを提供できる場合は同じepoch IDを返します。
- epoch変更または時刻後退を検出したRuntimeは、Commandの新規admissionを`CLOCK_UNCERTAIN`で拒否します。
- EventFactはno-deadlineですが、audit時刻を確定できない場合はdiscardを拒否します。
- Entropy `fill`は全byteを書けた場合だけOKです。partial fillはfailureです。

Entropy consumption / Runtime-generated ID:

- Core entropy calls are owner-thread serialized and consume candidates in this exact order. Runtime createの最初のID drawは`metrics_epoch_id`、新規admissionで全non-entropy validation/idempotency/authorization/capacity preflight成功後の次drawは`transaction_id`、各Applicationまたはremote-cancel `ATTEMPT_PREPARE`の次drawは`attempt_id`です。
- 各candidateは`entropy.fill(..., 16)`のexact 16 bytesをbyte order変換せず使用します。Handle、service、delivery token（context ID=transaction ID）、transaction sequence、reason、caller-supplied event/operation IDにはentropyを消費しません。ALREADY/REJECTED/conflict、attemptを作らないretry pollも消費しません。
- metrics/transaction/attemptそれぞれ1 IDにつき最大4 fill callsです。Port failure、partial fill、all-zeroの各callは全3種の4-call budgetを1消費します。Transaction/attemptだけは下記retained indexとのcollisionも1消費します。Valid candidateを得た時点で停止します。
- `metrics_epoch_id`はstrict-unique identityではなく、createごとにfresh entropyからdrawするnon-zero observability labelです。Retained collision indexを持たず、collision checkを行いません。Consumerは一意性や順序を推論せず、Runtime ID、`started_clock_epoch_id`、`started_at_ms`と一緒にobservability scopeを識別します。
- transaction IDは同じstorage namespaceのactive/retained transaction ID、attempt IDはactive/retained attempt ID indexに対してuniqueでなければなりません。Collision check/indexはrestartを跨ぎ、attempt ID index追加はATTEMPT_PREPARE recordと同じFULL transactionです。Network duplicateは既存attempt IDを保ち、logical retryだけがnew IDをdrawします。
- Retained attempt indexへ入るのは当該Runtimeがentropyから生成したApplication attempt IDとcancel-attempt IDだけです。Inbound messageがechoしたremote attempt IDは追加しません。各entryはparent transaction ID、Application/Cancel kind、attempt recordへbindingし、parentがnon-terminalの間とterminal transaction retention中は保持します。Exclusive retention endは[17章](17-foundation-domain-store.md)のCLEANUP_PLANを作り、ATTEMPT detailをbounded FULL batchで先に削除できます。Attempt index削除phaseではdurable namespace reuse fenceを立ててnew attempt allocationを停止し、全index削除後のFINALIZEでparent/idempotency/evidence/resourceをreleaseしてfenceを外します。Finalize authoritative commit前はcandidate再利用不可、各batch COMMIT_UNKNOWNはplan generation/member truthで解決します。M1aのID uniqueness保証はactive + retained + cleanup-fenced境界までで、永久tombstoneは保証しません。
- 4 callsでvalid candidateを得られなければ`NINLIL_E_ENTROPY`です。Runtime createはhandleを返さず、新規admissionはtransaction/ownershipを作らず、ATTEMPT_PREPAREはrecord/permit/Bearer sendを一切作りません。既存Runtimeはhealth `DEGRADED`となり、同じstepでfallback PRNG、clock、device ID、counterを使いません。
- Storage collision lookup自体のfailureはentropy failureへ変換せず、対応するstorage API statusです。Deterministic TEST providerのcounter advance/failure semanticsは14章が正本ですが、Coreの最大4 call順は本節が正本です。

### 5.3 Storage Port

```c
#define NINLIL_STORAGE_OK                  ((ninlil_storage_status_t)0u)
#define NINLIL_STORAGE_NOT_FOUND           ((ninlil_storage_status_t)1u)
#define NINLIL_STORAGE_BUFFER_TOO_SMALL    ((ninlil_storage_status_t)2u)
#define NINLIL_STORAGE_NO_SPACE            ((ninlil_storage_status_t)3u)
#define NINLIL_STORAGE_IO_ERROR            ((ninlil_storage_status_t)4u)
#define NINLIL_STORAGE_CORRUPT             ((ninlil_storage_status_t)5u)
#define NINLIL_STORAGE_COMMIT_UNKNOWN      ((ninlil_storage_status_t)6u)
#define NINLIL_STORAGE_BUSY                ((ninlil_storage_status_t)7u)
#define NINLIL_STORAGE_UNSUPPORTED_SCHEMA  ((ninlil_storage_status_t)8u)

#define NINLIL_STORAGE_READ_ONLY           ((ninlil_storage_mode_t)1u)
#define NINLIL_STORAGE_READ_WRITE          ((ninlil_storage_mode_t)2u)

#define NINLIL_DURABILITY_VOLATILE         ((ninlil_durability_t)1u)
#define NINLIL_DURABILITY_CHECKPOINTED     ((ninlil_durability_t)2u)
#define NINLIL_DURABILITY_FULL             ((ninlil_durability_t)3u)

typedef struct ninlil_storage_capacity {
    NINLIL_STRUCT_HEADER;
    uint64_t max_entries;
    uint64_t used_entries;
    uint64_t max_bytes;
    uint64_t used_bytes;
} ninlil_storage_capacity_t;

typedef struct ninlil_storage_ops {
    NINLIL_STRUCT_HEADER;
    void *user;

    ninlil_storage_status_t (*open)(
        void *user,
        ninlil_bytes_view_t storage_namespace,
        uint32_t expected_schema,
        ninlil_storage_handle_t *out_handle);

    void (*close)(void *user, ninlil_storage_handle_t handle);

    ninlil_storage_status_t (*begin)(
        void *user,
        ninlil_storage_handle_t handle,
        ninlil_storage_mode_t mode,
        ninlil_storage_txn_t *out_txn);

    ninlil_storage_status_t (*get)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_bytes_view_t key,
        ninlil_mut_bytes_t *inout_value);

    ninlil_storage_status_t (*put)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_bytes_view_t key,
        ninlil_bytes_view_t value);

    ninlil_storage_status_t (*erase)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_bytes_view_t key);

    ninlil_storage_status_t (*iter_open)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_bytes_view_t prefix,
        ninlil_storage_iter_t *out_iter);

    ninlil_storage_status_t (*iter_next)(
        void *user,
        ninlil_storage_iter_t iter,
        ninlil_mut_bytes_t *inout_key,
        ninlil_mut_bytes_t *inout_value);

    void (*iter_close)(void *user, ninlil_storage_iter_t iter);

    ninlil_storage_status_t (*capacity)(
        void *user,
        ninlil_storage_handle_t handle,
        ninlil_storage_capacity_t *out_capacity);

    ninlil_storage_status_t (*commit)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_durability_t durability);

    ninlil_storage_status_t (*rollback)(void *user, ninlil_storage_txn_t txn);
} ninlil_storage_ops_t;
```

Storage contract:

- Coreは`open` / `begin` / `iter_open`のout handleをcall前NULLにします。`OK`は対応handle non-NULL、non-OKはNULLが唯一のvalid shapeです。`OK + NULL`は`NINLIL_E_STORAGE_CORRUPT`です。non-OK + non-NULLはprovider contract corruptionとして、open handleは`close`、transactionは`rollback`、iteratorはparent txnがliveなら`iter_close`をexactly 1回呼んでconsumeした後、original statusでなく`NINLIL_E_STORAGE_CORRUPT`を返します。Cleanup resultはcorruption statusを上書きせず、そのopaque handleを再利用しません。
- `capacity`前にCoreはcurrent ABI header/reservedとnumeric zeroを設定します。`OK`はheader/reservedを維持し、`max_entries > 0`、`max_bytes > 0`、`used_entries <= max_entries`、`used_bytes <= max_bytes`の全fieldを返します。Non-OKはheader/reserved以外numeric all-zeroです。OK partial/invalid、non-OK poison、unknown statusはStorage corruptionで、値をcapacity判断へ使用しません。
- 1 exact storage namespaceにつきactive M1a Runtime writer leaseは最大1つです。`open`成功がleaseを取得し、clean `close`が解放します。同じnamespaceの2個目openはfirst handleがliveな間`NINLIL_STORAGE_BUSY`/NULL handleで、`runtime_create`は`NINLIL_E_WOULD_BLOCK`です。別owner thread/callback/Bearer handleで同じjournalをmulti-writer運用しません。
- Process crashでは`close`を偽装せず、Storage providerのcrash-safe exclusive lock/session recoveryがdead ownerを確認してleaseを解放した後だけreopenを許します。Dead確認前はBUSY、確認後のfirst reopenがincomplete transaction recoveryとRECOVERY_FENCEを完了します。Stale handle/generationのoperationは成功しません。
- 1 handleにつき同時に開けるwrite transactionは1つです。nested transactionは禁止です。
- read transactionはbegin時点のstable snapshotを提供します。
- keyは1〜255 byte、valueは0〜`NINLIL_M1A_MAX_STORAGE_VALUE_BYTES`（inclusive）です。Coreもproviderもこれを超えるsingle valueを発行/受理せず、providerはmutation前に`NINLIL_STORAGE_NO_SPACE`を返します。Total entry/byte limitは`capacity.max_entries/max_bytes`で別に検査します。
- Storage `put`が`OK`を返す場合、providerはreturn前にkey/valueをtransaction-owned stagingへdeep-copy済みでなければなりません。Callerはreturn直後から両bufferを再利用できます。Error時にproviderはcaller bufferのownershipを取得せず、transaction stagingも変更しません。`commit` / `rollback`によるtransaction consume後はstagingを破棄します。SQLite providerはbind時に即時copyまたは`SQLITE_TRANSIENT`相当を用い、caller buffer lifetimeへ依存しません。
- M1a CoreのREAD_WRITE planはbegin snapshotからcanonical final viewを先に導出し、各final keyをfinal encoded valueで最大1回`put`し、finalで不存在のbegin keyを最大1回`erase`します。Transient value、同じkeyの反復replace、put後eraseは生成しません。Call順にかかわらず各中間viewのkey/valueはbegin viewまたはfinal viewのいずれかからだけ選ばれます。Coreは`begin_entries`/`final_entries`と`begin_bytes`/`final_bytes`をchecked加算で`staging_*`へ合成し、overflowはmutation 0の`NINLIL_STORAGE_CORRUPT`（fail closed）です。各viewは`begin_* <= max_*`かつ`final_* <= max_*`を満たす必要があり、超えるplanはStorage call前に`NO_SPACE`またはCore contract failureとしてrejectします。`2 * max_*`とのu64比較は不要です（各側がmax以内かつchecked sumが成功すれば十分）。全named operation、bounded cleanup batch、destroy recovery groupを含むM1a operation builderはこのpreconditionを満たしてからStorage callを開始します。
- M1a providerは、上記Core planが作る中間viewについて、begin viewとfinal viewのunionに相当するentry/byteをstagingできなければなりません。これはFULL対応と同じplatform preconditionで、public ABIに別capability field/queryを追加しません。例えばcommitted 32件からdistinct 32件を先にputした64件viewは必須受理です。65件目はM1a Coreが生成してはならない範囲外であり、直接Storage ABIを使うcallerへproviderがmutation 0の`NO_SPACE`を返してもよいです。Final-net capacityはcommit時に別途検査し、最終viewが`capacity.max_*`以内ならput-before-eraseのcall順だけを理由に拒否しません。capacity maximaに`UINT64_MAX / 2`上限は課しません。
- iteratorはprefix一致keyをunsigned byte lexicographic昇順で1回ずつ返します。
- `iter_next`終端は`NINLIL_STORAGE_NOT_FOUND`です。
- `get` / `iter_next`のmutable buffer規則は次のclosed tableに従います。Input `length != 0`、capacity/data nullability違反では`NINLIL_STORAGE_CORRUPT`を返し、length/dataを変更しません。次表はvalid inputにだけ適用します。

| Status | `length` output | Data mutation |
| --- | --- | --- |
| `OK` | exact returned byte count（0〜capacity） | `[0, length)`だけをexact bytesで書き、`[length, capacity)`は変更しない |
| `BUFFER_TOO_SMALL` | required byte count。`get`ではstrictly capacityより大、`iter_next`ではpairの少なくとも一方がそのcapacityより大 | data全体を変更しない |
| `NOT_FOUND` | 0 | data全体を変更しない。`get`はmissing key、`iter_next`はend |
| other error | 0 | data全体を変更しない |

`iter_next`はkey/valueの2 bufferをatomic pairとして扱います。どちらか一方でも不足なら`BUFFER_TOO_SMALL`で、**両方**の`length`へそれぞれのrequired countを書き、両data bufferを変更しません。Success時だけ両方を同じiterator rowから書いてiteratorを1 row進めます。BUFFER_TOO_SMALL/errorではiterator positionを進めません。Endでは両lengthを0にします。
- `commit`はtxn handleを常にconsumeします。戻り後にrollbackしてはいけません。
- `FULL`のOKは、process/power failure後のreopenでtransaction全体が見えることを意味します。
- M1a Coreがdurable mutationで`commit`へ渡すdurabilityは常に`NINLIL_DURABILITY_FULL`です。`VOLATILE` / `CHECKPOINTED`はforward ABI valueであり、M1a Coreは生成しません。Storage ABIにcapability queryはないため、Runtime create/register時に「FULL対応」をdynamic判定しません。M1aへ供給するStorage PortはFULL commit semanticsを実装するplatform preconditionで、満たさないPortはAPI statusでdegradeするのではなく非準拠です。
- `COMMIT_UNKNOWN`時はtxn handleが無効で、Runtimeはdegradedへ入り、storageをreopenしてrecordの有無を確認します。
- `erase`のmissing keyはOKです。
- `capacity`成功時のshapeは上記closed ruleです。available entries/bytesはCoreがchecked subtractionで導出します。違反はstorage corruptionです。
- `rollback`は戻り値にかかわらずtxnをconsumeします。`OK`以外ではRuntimeをDEGRADEDへ移し、同じtxnを再利用しません。
- iteratorは親transaction所有です。`iter_close`はtransactionがACTIVEの間に明示closeする場合だけ、そのiteratorを1回consumeします。
- `commit`と`rollback`はtransactionと、その時点で未closeの全child iteratorを**暗黙にconsume/close**します。戻り値にかかわらず、Coreはその後childへ`iter_close`、`iter_next`を呼びません。Portは暗黙close済みiterator resourceをtransaction consumeの一部として解放します。
- `close`と明示`iter_close`はfailureを報告しないcleanup operationです。Coreはvalid handle/iteratorだけを渡し、同じresourceを二重closeしません。
- `close`時にlive txn/iteratorがあってはなりません。

### 5.4 Bearer Port

Bearer ABIはSimulator用logical transportです。Public radio wireではありません。

```c
#define NINLIL_BEARER_OK                   ((ninlil_bearer_status_t)0u)
#define NINLIL_BEARER_EMPTY                ((ninlil_bearer_status_t)1u)
#define NINLIL_BEARER_WOULD_BLOCK          ((ninlil_bearer_status_t)2u)
#define NINLIL_BEARER_UNAVAILABLE          ((ninlil_bearer_status_t)3u)
#define NINLIL_BEARER_DENIED               ((ninlil_bearer_status_t)4u)
#define NINLIL_BEARER_LOST_UNKNOWN         ((ninlil_bearer_status_t)5u)
#define NINLIL_BEARER_CORRUPT              ((ninlil_bearer_status_t)6u)

#define NINLIL_BEARER_MESSAGE_APPLICATION  ((ninlil_bearer_message_kind_t)1u)
#define NINLIL_BEARER_MESSAGE_RECEIPT      ((ninlil_bearer_message_kind_t)2u)
#define NINLIL_BEARER_MESSAGE_DISPOSITION  ((ninlil_bearer_message_kind_t)3u)
#define NINLIL_BEARER_MESSAGE_CANCEL_REQUEST ((ninlil_bearer_message_kind_t)4u)
#define NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED ((ninlil_bearer_message_kind_t)5u)
#define NINLIL_BEARER_MESSAGE_CANCEL_RESULT ((ninlil_bearer_message_kind_t)6u)

#define NINLIL_BEARER_SEND_ACCEPTED        ((ninlil_bearer_send_kind_t)1u)
#define NINLIL_BEARER_SEND_DURABLE_CUSTODY ((ninlil_bearer_send_kind_t)2u)

typedef struct ninlil_party {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t runtime_id;
    ninlil_id128_t application_instance_id;
    ninlil_local_identity_t local_identity;
} ninlil_party_t;

#define NINLIL_TARGET_HAS_DEVICE           ((uint32_t)1u << 0)
#define NINLIL_TARGET_HAS_INSTALLATION     ((uint32_t)1u << 1)
#define NINLIL_TARGET_HAS_SITE             ((uint32_t)1u << 2)

typedef struct ninlil_concrete_target {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t target_runtime_id;
    ninlil_id128_t target_application_instance_id;
    ninlil_id128_t device_id;
    ninlil_id128_t installation_id;
    ninlil_id128_t site_domain_id;
    uint64_t binding_epoch;
    uint64_t membership_epoch;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_concrete_target_t;

typedef struct ninlil_service_identity {
    NINLIL_STRUCT_HEADER;
    ninlil_text_id_t namespace_id;
    ninlil_text_id_t service_id;
    ninlil_text_id_t schema_id;
    uint64_t descriptor_revision;
    ninlil_digest256_t descriptor_digest;
    uint16_t schema_major;
    uint16_t schema_minor;
    ninlil_family_t family;
} ninlil_service_identity_t;

typedef struct ninlil_bearer_message {
    NINLIL_STRUCT_HEADER;
    ninlil_bearer_message_kind_t kind;
    uint32_t flags;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t event_id;
    ninlil_party_t source;
    ninlil_concrete_target_t target;
    ninlil_service_identity_t service;
    ninlil_digest256_t content_digest;
    uint64_t generation;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    ninlil_evidence_stage_t required_evidence;
    ninlil_evidence_stage_t receipt_stage;
    ninlil_disposition_t disposition;
    ninlil_effect_certainty_t effect_certainty;
    ninlil_retry_guidance_t retry_guidance;
    ninlil_cancel_kind_t cancel_kind;
    uint64_t retry_delay_ms;
    ninlil_time_sample_t evidence_time;
    ninlil_bytes_view_t payload;
    ninlil_bytes_view_t evidence;
} ninlil_bearer_message_t;

typedef struct ninlil_bearer_send_result {
    NINLIL_STRUCT_HEADER;
    ninlil_bearer_send_kind_t kind;
    uint32_t reserved_zero;
    uint64_t availability_epoch;
} ninlil_bearer_send_result_t;

typedef struct ninlil_bearer_state {
    NINLIL_STRUCT_HEADER;
    uint64_t availability_epoch;
    uint32_t available;
    uint32_t reserved_zero;
} ninlil_bearer_state_t;
```

Message field rules:

- `flags`はM1aでは0です。全kindでtransaction、source、target、service、content digest、required evidence、family metadata、deadline bindingをoriginal admitted Applicationとexact一致させます。EventFactはevent ID non-zero/generation 0、DesiredStateCommandはevent ID zero/generation non-zeroです。
- Forward orientationは`APPLICATION`と`CANCEL_REQUEST`です。`message.source`はoriginal admission source party、`message.target`はoriginal concrete targetとexact一致します。
- Reverse orientationは`RECEIPT`、`DISPOSITION`、`CUSTODY_ACCEPTED`、`CANCEL_RESULT`です。Reverse sourceはoriginal targetをpartyへexact変換します。runtime/application IDはtargetの同名ID、local identityのdevice/installation/site/flags/binding/membershipはtargetの対応fieldです。Reply targetはoriginal source partyをconcrete targetへ逆変換し、runtime/application/local identity全fieldをexact再構成します。
- Reverse `RECEIPT`/`DISPOSITION`/`CUSTODY_ACCEPTED`はtriggerしたAPPLICATIONのnon-zero attempt IDをechoします。Remote cancelはoriginal Application attemptとは別のnon-zero cancel attempt IDをexactly 1つ作り、`CANCEL_RESULT`が`CANCEL_REQUEST`のIDをechoします。
- service identity/revision/digest、content digest、EventFact event IDまたはCommand generation、deadline epoch/time、evidence grace、required evidenceをkindにかかわらずechoします。echo不能なfieldを推測・zero補完しません。

| Kind | receipt_stage | disposition / certainty / guidance / delay | cancel_kind | evidence_time | payload | evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `APPLICATION` | `NONE` | `NONE / NONE / NEVER / 0` | 0 | all-zero | exact logical payload | empty |
| `RECEIPT` | supported non-zero stage | `NONE / NONE / NEVER / 0` | 0 | valid required | empty | 0〜128 bytes |
| `DISPOSITION` | `NONE` | 7.2 combination tableのexact tuple | 0 | all-zero | empty | empty |
| `CANCEL_REQUEST` | `NONE` | `NONE / NONE / NEVER / 0` | 0 | all-zero | empty | empty |
| `CUSTODY_ACCEPTED` | `NONE` | `NONE / NONE / NEVER / 0` | 0 | all-zero | empty | empty |
| `CANCEL_RESULT` | `NONE` | `NONE / NONE / NEVER / 0` | `FENCED_BEFORE_DISPATCH` or `TOO_LATE_EFFECT_POSSIBLE` | all-zero | empty | empty |

- `RECEIPT`の`evidence_time`はReceiver Runtimeがapplication result/ingress evidenceをdurably commitしたlocal clock sampleです。`RECEIPT`以外ではnested struct全体（ABI headerを含む）がzeroです。RECEIPTではnon-zero clock epoch ID、known trust値、monotonic sampleがrequiredです。uncertain trustも明示値として運び、trustedと偽装しません。
- Bearer `DISPOSITION`にreason fieldはありません。Receiverは7.2表のDisposition/certainty/guidance tupleを送信し、sender reducerが同表のstable reasonへexact写像します。
- retryable Dispositionをdurably ingressしたsenderは、自身のlocal clockで`retry_not_before = checked(now_ms + max(descriptor.retry_backoff_ms, retry_delay_ms))`を作ります。remote absolute clockへ依存しません。
- `CANCEL_REQUEST/CANCEL_RESULT`はDesiredStateCommandだけです。`CUSTODY_ACCEPTED`はApplication Receipt/evidenceではなく、receiverがpayloadとbindingをFULL commitした後のtransport observationです。
- kindで未使用のID、enum、view、nested valueは上表どおりzero/emptyです。
- DesiredStateCommandの全message kindはnon-zero `deadline_clock_epoch_id`とfinite `absolute_effect_deadline_ms`を持ち、EventFactではepoch ID all-zero、deadline `NINLIL_NO_DEADLINE`です。
- source partyのruntime/application IDとlocal identity snapshotは全message kindでstable provenanceです。ReceiverはBearer endpoint addressから推測して補完せず、persistしたenvelope bindingと照合します。
- `receive_next`後、Coreはorientation、local endpoint identity、original admission/inbox binding、echo fieldをreducer/storage ingress前に検証します。不正direction、source/target reconstruction不一致、attempt/transaction/service/content/family/deadline binding不一致はreducerへ入力せず、messageをreleaseしてinvalid-ingress diagnosticへ記録します。不正messageへのReceipt/Dispositionで応答しません。
- M1aでclock timeを比較可能なのはclock epoch IDがexactly一致する場合だけです。DesiredState ControllerはReceiptのissuer evidence timeがadmission deadline epochと一致するときだけdeadline proofへ使用します。それ以外はController側のdurable Receipt ingress timeを保守的に使い、これもdeadline epochと一致せず期限内を証明できなければ`deadline_verdict`をMETへしません。EventFactはno-deadlineですがaudit evidenceとしてsampleを保持します。

Concrete target validation:

- `target_runtime_id`と`target_application_instance_id`は常にnon-zeroです。
- `flags`は`HAS_DEVICE | HAS_INSTALLATION | HAS_SITE`の範囲だけです。各flagが1なら対応IDはnon-zero、0なら対応IDはall-zeroです。
- `binding_epoch`はdeviceまたはinstallationがある場合non-zero、それ以外は0です。`membership_epoch`はsiteがある場合non-zero、それ以外は0です。
- M1a Submissionのtarget countはController/Endpointともexactly 1です。0または2以上は構文的に有効なSubmission rejectionで、reasonは`TARGET_COUNT_UNSUPPORTED`です。

```c
typedef struct ninlil_tx_permit {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t permit_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t clock_epoch_id;
    uint64_t expires_at_ms;
} ninlil_tx_permit_t;

typedef struct ninlil_bearer_ops {
    NINLIL_STRUCT_HEADER;
    void *user;

    ninlil_bearer_status_t (*open)(
        void *user,
        const ninlil_id128_t *runtime_id,
        ninlil_role_t role,
        ninlil_bearer_handle_t *out_handle);

    void (*close)(void *user, ninlil_bearer_handle_t handle);

    ninlil_bearer_status_t (*send)(
        void *user,
        ninlil_bearer_handle_t handle,
        const ninlil_tx_permit_t *permit,
        const ninlil_bearer_message_t *message,
        ninlil_bearer_send_result_t *out_result);

    ninlil_bearer_status_t (*receive_next)(
        void *user,
        ninlil_bearer_handle_t handle,
        ninlil_bearer_message_t *out_message);

    void (*release_received)(
        void *user,
        ninlil_bearer_handle_t handle,
        ninlil_bearer_message_t *message);

    ninlil_bearer_status_t (*state)(
        void *user,
        ninlil_bearer_handle_t handle,
        ninlil_bearer_state_t *out_state);
} ninlil_bearer_ops_t;
```

Bearer ownership:

- Coreは`open`のout handleをcall前NULLにします。`OK + non-NULL`とnon-OK + NULLだけがvalid shapeです。`OK + NULL`はcreate `NINLIL_E_DEGRADED`、non-OK + non-NULL/unknown statusはunexpected handleを`close` exactly 1回して`NINLIL_E_DEGRADED`です。Handleをpublish/reuseせず、cleanup statusでprimary resultを上書きしません。
- `send`がACCEPTEDを返す前に、messageの全viewをdeep copyします。
- WOULD_BLOCK/UNAVAILABLE/DENIED/LOST_UNKNOWN時はBearerがmessageを保持しません。
- `receive_next`のviewはBearer所有で、`release_received`まで有効です。
- Runtimeは必要なdataをstorage/allocatorへcopyしてからreleaseします。
- `receive_next`がEMPTYの場合、out messageはinvalid/zeroです。
- `availability_epoch`はBearer provider所有のnon-zero monotonic state revisionです。`available`の0↔1変化ごとにchecked strict incrementします。さらにavailable=1のままでも、send queue full/WOULD_BLOCK→space available等、以前blockしたworkの成功可能性が実際に改善したtransitionではstrict incrementします。
- `bearer_state.available`は0/1だけで、send result/stateはcall return時の同じcurrent `availability_epoch`を返します。Unavailable中もepochはnon-zeroで、available=0自体をfresh機会と解釈しません。
- poll、send成功、available bitもblock改善条件も同一の通知、Runtime restartだけではincrementしません。Provider/harnessはrestartを跨いでcurrent epoch/available/blocked historyを保持し、完全なscenario/provider resetだけが新namespaceへ戻せます。increment不能ではwrapせずproviderをunavailable/fatalとします。同じepochで異なる`available`を返すことはprovider contract failureです。
- Runtimeはstrictly larger epochのvalid Bearer stateをnamespace-level `latest availability epoch + available flag`として1 FULL commitし、Eventごとのrecordをそのcommitへ一括更新しません。EventFactがPARKED_RETRYへ入るcommitはその時点のlatest epochを`last_seen_availability_epoch`へsnapshotします。後から`available=1`のstrictly larger epochを観測したとき、eligibleな各parked Event ownerがscheduler順に独立して1回だけconsumeし、1 Event / 1 epochにつき最大1つのnew retry cycleを作ります。Exact same epoch/flagと古いepochはno-op、same epoch/different flagはcontract failureでresume 0です。
- 同じ/古いBearer epochをmanagement/diagnostic resultへ理由付きで公開する場合だけ`NINLIL_REASON_STALE_AVAILABILITY_EPOCH`を使用します。このreasonはBearer availability専用で、Runtime resource capacityには使用しません。
- `ninlil_capacity_entry_t.capacity_epoch`はRuntime resourceごとの別observability domainです。Bearer `availability_epoch`と数値比較、代入、共通counter扱いをしてはなりません。Capacity epochへ`NINLIL_REASON_STALE_AVAILABILITY_EPOCH`を写像しません。

Bearer output shape/statusはclosedです。ProviderはCoreがzero初期化したoutputを次表以外へ部分変更しません。

| Method / return | Required output | Core action |
| --- | --- | --- |
| `send: OK` | current header、kind=`ACCEPTED` or `DURABLE_CUSTODY`、reserved=0、current non-zero availability epoch | accepted path |
| `send: WOULD_BLOCK/UNAVAILABLE/DENIED/LOST_UNKNOWN/CORRUPT` | current header、kind=0、reserved=0、current non-zero availability epoch | 5.5 closed send matrix |
| `send: EMPTY/unknown`、または上記shape違反 | shapeを信用しない | port contract fence。possible delivery扱い |
| `receive_next: OK` | current outer/nested headersと5.4のexact valid message shape | provider-owned message。durable copy/drop後`release_received` exactly 1 |
| `receive_next: EMPTY/WOULD_BLOCK/UNAVAILABLE` | outer message全体all-zero | messageなし。release 0。EMPTYはquiescent、他2つはnormal temporary no-input |
| `receive_next: DENIED` | all-zero | first step error `NINLIL_E_DEGRADED`、APPLICATION_FAILED health cause、release 0 |
| `receive_next: LOST_UNKNOWN/CORRUPT/unknown`、non-OK+non-zero output | all-zero required | first step error `NINLIL_E_DEGRADED`、OUTCOME_UNKNOWN health cause、release 0 |
| `receive_next: OK`だがpartial/invalid message | provider owns returned buffer | semantic reducerへ入れずbounded invalid diagnostic後`release_received` exactly 1 |
| `state: OK` | current header、non-zero epoch、available 0/1、reserved=0 | valid availability observation |
| `state: WOULD_BLOCK/UNAVAILABLE` | state全体all-zero | no availability input、normal temporary |
| `state: DENIED` | all-zero | first step error DEGRADED/APPLICATION_FAILED |
| `state: EMPTY/LOST_UNKNOWN/CORRUPT/unknown`、partial/non-OK+non-zero | all-zero required | first step error DEGRADED/OUTCOME_UNKNOWN |

Actual Bearer `send`は、同じprovider domainのdurable namespace Bearer stateが既に存在し、その`availability_epoch`がnon-zeroの場合だけ呼べます。`runtime_step` stage 3のpoll後も該当stateがabsentならsend候補を実行せず、Bearer callは0です。Call直前にdurable latest epochを`fallback_epoch`として固定し、send対象ATTEMPTまたはREVERSE_REPLYが保持するprior non-zero availability epochと同じBearer epoch domain内だけで比較します。Clock/capacity/別providerのepochと比較してはなりません。

Send resultのavailability epochは、closed output shapeを満たすnon-zero値で、`fallback_epoch`および対象recordのprior availability epoch以上ならusableです。Equalはvalidで、strictly smallerだけをregressedとします。Call中にprovider stateが進みreturned epochがfallbackより大きい場合もvalidで、対象recordへreturned valueを保存し、namespace stateは次のvalid stage 3 pollで追従します。Zero、shape違反、unknown status、またはregressed valueは信用せず、当該sendをpossible-delivery contract fenceとして扱いますが、call済みobservation自体を握りつぶしません。Availability fieldを持つsend recordには`max(fallback_epoch, prior availability epoch)`を保存し、synthetic epochを作りません。したがってfirst invalid returnもautomatic-send可能なPENDINGへ残さず、message-kind別closed matrixへ進めます。Send return後・observation commit前crashだけがold PENDING/WAITINGを保持して再送可能です。

`receive_next: OK` messageのdurable ingress ownership boundaryは次です。Coreは必要byteをowned stagingへcopyし、namespace-global ordered-input counterのnext value、INGRESS slot/message、logical timeを`runtime.before_ingress_copy_commit` / `runtime.after_ingress_copy_commit`間の1 FULL transactionへcommitします。

| Ingress copy result | Provider buffer | Durable/result behavior |
| --- | --- | --- |
| commit OK | commit後`release_received` exactly 1 | Stage-4 cut後のcopyなので次stepからreduce可。release直後`ingress_processed += 1`、current-time more_workを残す |
| definite begin/write/commit failure | rollback確定後release exactly 1 | durable input 0、reply/ACK/callback 0、対応first step errorで停止。Sender retryへ委ねる |
| COMMIT_UNKNOWN | return観測後release exactly 1、namespace fence | step=`NINLIL_E_STORAGE_COMMIT_UNKNOWN`。Reopenでcopy+sequenceが全てある/全てないへ収束し、ない場合もfalse reply 0 |
| capacity/allocator preflight block | blocked flag commit後release exactly 1 | copy/sequence/reply 0、bounded drop。Sender retryへ委ねる |

Namespace `last_assigned_ordered_input_sequence`はuint64、new namespaceで0、first assigned sequence=1です。Bearer ingress copyと、public management inputがdurable ordered reducerへmutationを追加するFULL transactionでchecked +1し、input record/owner attachmentとatomic persistします。Restartでrollback/renumberせず、same-time/same-priority tie-breakはこのsequence昇順です。Read-only/ledger replay/conflict/semantic no-op management resultはsequenceを消費しません。MAXでは新しいdurable inputを順序付けられないためstepは`receive_next`を呼ばず、mutationを要するmanagement APIは`NINLIL_E_DEGRADED`/invalid result、Runtime health=`COUNTER_EXHAUSTED`です。Wrap/fallback counterを使いません。

Bearer providerにCore wake callback ABIはありません。Provider state/queue changeを所有するplatform integrationはowner event loopへRuntime wakeを通知し、callerが`runtime_step`を呼びます。各stepは11.0の順で`state()`をexactly 1回pollするため、通知がcoalesceしてもcurrent epochを取得します。Poll自体、Runtime restart、同値stateでepochを増やしません。

### 5.5 TEST Tx Gate

```c
#define NINLIL_TX_GATE_OK                  ((ninlil_tx_gate_status_t)0u)
#define NINLIL_TX_GATE_DENIED              ((ninlil_tx_gate_status_t)1u)
#define NINLIL_TX_GATE_TEMPORARY           ((ninlil_tx_gate_status_t)2u)

typedef struct ninlil_tx_request {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_bearer_message_kind_t message_kind;
    uint32_t logical_bytes;
    ninlil_digest256_t content_digest;
} ninlil_tx_request_t;

typedef struct ninlil_tx_gate_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_tx_gate_status_t (*acquire)(
        void *user,
        const ninlil_tx_request_t *request,
        const ninlil_time_sample_t *now,
        ninlil_tx_permit_t *out_permit);
    void (*release_unused)(void *user, const ninlil_tx_permit_t *permit);
} ninlil_tx_gate_ops_t;
```

Runtimeは全Bearer send前にpermitを取得します。Permitの`clock_epoch_id`はacquireへ渡した`now.clock_epoch_id`と一致するnon-zero値です。Permit validityはexclusive endで、Bearer `send`はNULL permit、attempt mismatch、clock epoch mismatch、`now_ms >= expires_at_ms`、reuseをDENIEDにし、未使用permitをreleaseします。M1aのproviderはTEST専用で、production complianceを表しません。

Coreは`out_permit`をcall前にall-zero初期化し、returnを次のclosed matrixで`TX_GATE_RESULT`へ正規化します。`TEMPORARY`/`DENIED`ではout permit全体がzero、`OK`ではABI header、non-zero permit/attempt/clock ID、request attempt exact match、clock epoch exact match、`expires_at_ms > now_ms`がrequiredです。

| Acquire result | Bearer invocation | Exact reducer meaning |
| --- | ---: | --- |
| `OK` + exact valid permit | 1を許可 | 次のpre-send durable gate/budgetを満たした後だけBearerへ渡す |
| `TEMPORARY` + zero permit | 0 | definite no-send / `NO_EFFECT_PROVEN`。Descriptor fixed backoffだけでbounded retry |
| `DENIED` + zero permit | 0 | definite no-send / policy denial。Commandは`FAILED_DEFINITIVE / APPLICATION_FAILED`、Eventは`PARKED_RETRY / APPLICATION_REMEDIATION`、cancelはprepared recordをdurably closedし`PENDING_REMOTE_FENCE`のまま |
| unknown status、non-OK+non-zero permit、またはOKだがpartial/mismatched/expired permit | 0 | provider contract fence。上記DENIEDと同じtransaction/event/cancel stateにし、Runtimeへ`OUTCOME_UNKNOWN` internal health causeをaddしてDEGRADED |

`TEMPORARY`はattempt prepare済みApplicationではその1 attemptを消費済みのままにし、Command/Eventともtimer epoch + `checked(now + descriptor.retry_backoff_ms)`をFULL commitします。Commandはbudget/deadline guard成立時だけRETRY_WAIT、Eventは8thならCYCLE_EXHAUSTED_TRANSIENTでparkし、それ以前はRETRY_WAITです。Cancelは同じprepared cancel attempt/messageを保持し、fixed backoff後にfresh acquireを行い、new entropy/attemptを作りません。Cached reverse Receipt/Disposition/Custody/CancelResultも同じmessageをfixed backoff後に再試行し、callback/result commitを繰り返しません。

`DENIED`/provider contract fenceではautomatic acquire retryを行いません。Cached reverse messageはdurable cacheを保持しますがautomatic sendを閉じ、duplicate exact requestによる通常のcached reply pathだけが将来new permitを取得できます。Provider contract fenceで`OK`かつpermit IDがnon-zeroならBearerへ渡す前に`release_unused`をexactly 1回呼び、それ以外は0回です。

Actual Bearer `send` returnも全message kindで次のclosed ownership/certainty matrixを使います。Coreはout resultをcall前にzero初期化します。

| Bearer return / out result | Message accepted possibility | Permit handling | Application send reducer |
| --- | --- | --- | --- |
| `OK` + exact `ACCEPTED` or `DURABLE_CUSTODY` + valid current epoch | yes | consumed、release 0 | `EFFECT_POSSIBLE`、Receipt待ち |
| `LOST_UNKNOWN` | yes/unknown | consumed-or-unknown、release 0 | `EFFECT_POSSIBLE`、Receipt待ち |
| `WOULD_BLOCK` or `UNAVAILABLE` | no | `release_unused` exactly 1、same permit reuse 0 | Commandはfixed-backoff no-effect retry、Eventはimmediate `PARKED_RETRY / BEARER_UNAVAILABLE` |
| `DENIED` | no | `release_unused` exactly 1、same permit reuse 0 | Commandは`FAILED_DEFINITIVE / APPLICATION_FAILED`、Eventは`PARKED_RETRY / APPLICATION_REMEDIATION` |
| `CORRUPT`、`EMPTY`、unknown status、`OK`だがpartial/unknown kind/zero or regressed epoch | possibleとしてfence | release 0 | `EFFECT_POSSIBLE`、Runtime `OUTCOME_UNKNOWN` health causeをaddしてDEGRADED。Commandはevidence close、EventはReceiptまたはexplicit lifecycleを待つ |

Application EventのWOULD_BLOCK/UNAVAILABLE/DENIEDによるearly parkはATTEMPT_PREPAREDで増えた`attempts_in_cycle`を戻さず、1〜8 attemptsのpartial cycleをcloseします。Public reasonは常に`EVENT_RETRY_CYCLE_PARKED`です。`CAPACITY_UNAVAILABLE` causeはvalid remote `CAPACITY_EXHAUSTED / NO_EFFECT_PROVEN` Dispositionによるearly parkだけで生成し、admission resource rejectionやstep budget exhaustionをparkへ偽装しません。Reverse cached messageのactual sendはWOULD_BLOCK/UNAVAILABLEだけfixed-backoff retry、DENIEDはautomatic close、accepted/unknownはautomatic duplicate send 0、corrupt/invalidはclose + Runtime DEGRADEDです。

Cached reverse Receipt/Disposition/CustodyAccepted/CancelResultはduplicate-safe at-least-once replyです。Durable cacheはsend state `PENDING`、`WAITING_RETRY`、`CLOSED_SENT_OR_UNKNOWN`、`CLOSED_DENIED`、`CLOSED_COUNTER_EXHAUSTED`だけを持ちます。PENDING/WAITINGだけがautomatic send可能です。CLOSED_COUNTER_EXHAUSTEDはsend operation/invocation counterがMAXへ到達したabsorbing stateで、timer zero、reply payload release済み、duplicateでもPENDINGへ戻しません。

- Actual send後、`runtime.before_reverse_send_observation_commit` / `runtime.after_reverse_send_observation_commit`間でstatus observationをFULL commitします。OK accepted/custody、LOST_UNKNOWN、CORRUPT/invalidは`CLOSED_SENT_OR_UNKNOWN`、DENIEDは`CLOSED_DENIED`、WOULD_BLOCK/UNAVAILABLEはfixed timer付き`WAITING_RETRY`です。
- Send return後・observation commit前crashではdurable stateがPENDING/WAITINGのためsame immutable replyを再送できます。Duplicateはreceiverのtransaction/attempt/service/content bindingでidempotentです。Observation commit後はrestartだけでautomatic resendしません。
- Exact duplicate inbound request/messageはCLOSED_SENT_OR_UNKNOWN/CLOSED_DENIED cached resultを再びPENDINGへするnew reply opportunityをFULL commitでき、application callback/result/custody mutationを繰り返しません。CLOSED_COUNTER_EXHAUSTEDはreopenせずsend 0です。Reopen可能stateではnew permitを取得し、same logical reply bytes/bindingを送ります。
- Observation commit failure/unknownではfalse closedを公開せずnamespace recoveryへ従います。Cancel REQUESTのsingle-send conservative gateとは別で、reverse duplicate-safe replyへcancel-request ruleを流用しません。

### 5.6 TEST Origin Authorization / Grant

```c
#define NINLIL_ORIGIN_AUTH_OK                ((ninlil_origin_auth_status_t)0u)
#define NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE ((ninlil_origin_auth_status_t)1u)
#define NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE ((ninlil_origin_auth_status_t)2u)

typedef struct ninlil_origin_authorization_request {
    NINLIL_STRUCT_HEADER;
    ninlil_environment_t environment;
    uint32_t reserved_zero;
    ninlil_party_t source;
    ninlil_concrete_target_t target;
    ninlil_service_identity_t service;
    ninlil_id128_t event_id;
    ninlil_digest256_t content_digest;
    ninlil_evidence_stage_t required_evidence;
    uint32_t payload_length;
    uint32_t active_spool_count;
    uint32_t admissions_in_current_window;
    uint64_t active_spool_bytes;
    uint64_t current_window_started_at_ms;
    ninlil_time_sample_t now;
} ninlil_origin_authorization_request_t;

typedef struct ninlil_origin_authorization_decision {
    NINLIL_STRUCT_HEADER;
    uint32_t allowed;
    ninlil_reason_t reason;
    ninlil_retry_guidance_t retry_guidance;
    uint32_t reserved_zero_head;
    ninlil_id128_t provider_id;
    uint64_t provider_revision;
    ninlil_digest256_t decision_digest;
    ninlil_id128_t grant_id;
    uint64_t grant_revision;
    ninlil_id128_t clock_epoch_id;
    uint64_t evaluated_at_ms;
    uint64_t valid_from_ms;
    uint64_t expires_at_ms;
    uint64_t retry_delay_ms;
    uint32_t max_payload_bytes;
    uint32_t max_active_spool_count;
    uint64_t max_active_spool_bytes;
    uint32_t rate_window_ms;
    uint32_t max_admissions_per_window;
    uint32_t max_attempts_per_retry_cycle;
    uint32_t reserved_zero_tail;
} ninlil_origin_authorization_decision_t;

typedef struct ninlil_origin_authorization_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_origin_auth_status_t (*evaluate)(
        void *user,
        const ninlil_origin_authorization_request_t *request,
        ninlil_origin_authorization_decision_t *out_decision);
} ninlil_origin_authorization_ops_t;
```

Contract:

- `evaluate`は新規EventFactのsyntax、schema、length、content digest、idempotency lookupを検査した後、resource reservation前に1回だけ呼びます。same key/same digestの既存admissionには再評価せず`ALREADY_ADMITTED`を返します。
- requestとそのnested viewはcall中だけborrowedです。Providerは保持しません。Coreはdecisionの全scalarをreturn時にcopyします。
- `ORIGIN_AUTH_OK`のdecisionは全fieldを設定します。`clock_epoch_id`はrequest `now.clock_epoch_id`とexact matchし、evaluated/valid-from/expiresの共通epochです。`allowed == 1`ではreason `NONE`、retry guidance `NEVER`、`retry_delay_ms == 0`、required ID/digestはnon-zero、`valid_from_ms <= evaluated_at_ms < expires_at_ms`、`evaluated_at_ms == request.now.now_ms`、`max_attempts_per_retry_cycle == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE`です。
- M1aのrequest rate windowはdescriptor `admission_window_ms`で`floor(now_ms / admission_window_ms)`から作り、`current_window_started_at_ms`と同じservice quota key/windowのcommit済みadmission count（candidate自身を含まない）を渡します。ALLOW decisionの`rate_window_ms`は同じ値、`max_admissions_per_window`はdescriptor上限以下でなければなりません。
- Origin request/decisionのgrant rateは件数だけです。ABI 0.1に`payload_bytes_in_current_window`やgrant byte-window fieldはなく、descriptor `max_payload_bytes_per_window`はprovider ALLOW validation後にCoreが自身のdurable quota recordで強制します。Providerがbyte counterを推測してdenyしてはなりません。Grant単位byte-windowはfield追加を伴う後続ABIです。
- `allowed == 0`ではreasonを`GRANT_INVALID`、`GRANT_EXPIRED`、`GRANT_LIMIT_EXCEEDED`、`RATE_EXHAUSTED`、`TARGET_UNAUTHORIZED`、`CLOCK_UNCERTAIN`のいずれかにし、不要なgrant/limit fieldはzeroにします。valid組合せは次だけです。

| Deny reason | retry guidance | retry_delay_ms |
| --- | --- | ---: |
| `GRANT_LIMIT_EXCEEDED` / `RATE_EXHAUSTED` | `RETRY_SAME_AFTER` | 0〜`NINLIL_M1A_MAX_RETRY_DELAY_MS` relative。0はdescriptor backoffだけ |
| `TARGET_UNAUTHORIZED` | `RETRY_MODIFIED` | 0 |
| `GRANT_INVALID` / `GRANT_EXPIRED` / `CLOCK_UNCERTAIN` | `RETRY_OPERATOR_ACTION` | 0 |

他の組合せはinvalid decisionです。
- Valid DENYは`provider_id`、`provider_revision`、`decision_digest`をnon-zero、`clock_epoch_id == request.now.clock_epoch_id`、`evaluated_at_ms == request.now.now_ms`にします。`grant_id`/`grant_revision`、`valid_from_ms`/`expires_at_ms`、max payload/active spool/rate/attempt limitはすべてzeroです。`retry_delay_ms`だけが上表で許された値、全reservedはzeroです。Allowed=0でprovider provenance/timeがzero/不一致、またはunused grant/limit fieldがnon-zeroならpartial/invalid decisionとしてprovider contract failureです。
- CoreはALLOWでも`source.runtime_id/application_instance_id/local_identity`、service/descriptor、target、payload、evidence、active spool、rate window、expiryをrequestとdecision limitsに対して再検査します。Provider ALLOW後、service inflight/window quota、grant payload/active spool/rate count、Runtime reservationのprospective値を検査します。Provider decisionはstorage capacity reservationではありません。
- providerが`ORIGIN_AUTH_OK`でvalid DENY decisionを返した場合だけ、`NINLIL_OK + SUBMISSION_REJECTED`とdecision reason/retry guidance/retry delayをそのまま返します。clock uncertainを正常decisionとしてdenyした場合も`REJECTED / CLOCK_UNCERTAIN`です。
- `ORIGIN_AUTH_TEMPORARY_FAILURE`はAPI `NINLIL_E_WOULD_BLOCK`、`ORIGIN_AUTH_PERMANENT_FAILURE`またはOKだがpartial/invalid decisionはAPI `NINLIL_E_DEGRADED`です。どちらもout resultを`SUBMISSION_INVALID`/zero assuranceにし、所有権はcaller、spoolは作りません。platform pointer/function欠落は`runtime_create`のinvalid platformです。platform failureをpolicy rejectionへ見せかけません。
- valid ALLOW decision、request binding、provider/grant identity、limit、evaluated time、decision digestはEventFact admissionと同じ`FULL` transactionへsnapshotします。commit前にADMITTEDを返しません。
- grant expiryは新規admissionだけを止めます。既にadmittedしたEventFactのcustody、retry、Receipt、resume、discardを遡及失効させません。
- provider/grant identity、revision、validity、decision digestはauthorization evidenceであり、canonical business submission digestへ含めません。
- M1a conformance providerはTEST専用です。M4のreal credential/grant backendはこのvtableの背後で置換し、Coreへfixture shortcutを追加しません。

全familyの新規admission exact orderは、syntax/schema/content → idempotency/event mapping lookup → trusted admission reference sample → transaction sequence headroom → scheduler owner sequence headroom → EventFactだけprovider exactly 1 call/decision validation/normal DENY → Core-owned service quotaとgrant prospective limit → Runtime reservation → transaction ID draw → one FULL admission commitです。ALREADY/conflictはclock/counter/provider/quota mutation 0です。どちらかのsequence counterがMAXなら`REJECTED / COUNTER_EXHAUSTED / RETRY_OPERATOR_ACTION / delay 0`でprovider/entropy/reservation 0です。Valid normal DENYはcounter headroom確認後にprovider tupleをそのまま返します。Valid ALLOW後は7.1の単一ordered tableにより、checked `payload.length`、`active_spool_count + 1`、`active_spool_bytes + payload.length + 2560`、`admissions_in_window + 1`をdecision limitsへ比較します。Grant payload/active spool超過は`GRANT_LIMIT_EXCEEDED / RETRY_SAME_AFTER / 0`、grant rate count超過は`RATE_EXHAUSTED / RETRY_SAME_AFTER / current window remaining`です。Binding/clock/required limit field自体がinvalidなALLOWだけをprovider contract failureとして`NINLIL_E_DEGRADED + SUBMISSION_INVALID`にします。

### 5.7 Platform aggregate

```c
typedef struct ninlil_platform_ops {
    NINLIL_STRUCT_HEADER;
    const ninlil_allocator_ops_t *allocator;
    const ninlil_execution_ops_t *execution;
    const ninlil_clock_ops_t *clock;
    const ninlil_entropy_ops_t *entropy;
    const ninlil_storage_ops_t *storage;
    const ninlil_bearer_ops_t *bearer;
    const ninlil_tx_gate_ops_t *tx_gate;
    const ninlil_origin_authorization_ops_t *origin_authorization;
} ninlil_platform_ops_t;
```

全pointerがrequired/non-NULLです。Runtimeはvtableをcopyしますが、各`user`とPort側resourceはRuntime destroy完了まで有効でなければなりません。

## 6. Runtime configとresource profile

```c
typedef struct ninlil_resource_limits {
    NINLIL_STRUCT_HEADER;
    uint32_t max_services;
    uint32_t max_nonterminal_transactions;
    uint32_t max_targets_per_transaction;
    uint32_t max_logical_payload_bytes;
    uint64_t max_durable_outbox_payload_bytes;
    uint32_t max_attempts_per_target_per_cycle;
    uint32_t max_cancel_attempts_per_transaction;
    uint32_t max_evidence_per_target;
    uint32_t max_retained_terminal_transactions;
    uint32_t max_nonterminal_deliveries;
    uint32_t max_event_spool_count;
    uint64_t max_event_spool_bytes;
    uint32_t max_result_cache_entries;
    uint32_t max_retained_dispositions;
    uint32_t max_ingress_per_step;
    uint32_t max_callbacks_per_step;
    uint32_t max_state_transitions_per_step;
    uint32_t max_bearer_sends_per_step;
    uint32_t max_deferred_tokens;
    uint32_t reserved_zero;
} ninlil_resource_limits_t;

typedef struct ninlil_runtime_config {
    NINLIL_STRUCT_HEADER;
    ninlil_role_t role;
    ninlil_environment_t environment;
    ninlil_id128_t runtime_id;
    ninlil_local_identity_t local_identity;
    ninlil_bytes_view_t storage_namespace;
    ninlil_resource_limits_t limits;
    uint64_t terminal_retention_ms;
    uint64_t result_cache_retention_ms;
    uint64_t observation_retention_ms;
    uint32_t reserved_zero;
} ninlil_runtime_config_t;
```

`NINLIL-FOUNDATION-SMALL-1` inclusive上限:

| Field | Controller | Endpoint |
| --- | ---: | ---: |
| max_services | 16 | 8 |
| max_nonterminal_transactions | 256 | 32 |
| max_targets_per_transaction | 1 | 1 |
| max_logical_payload_bytes | 1024 | 1024 |
| max_durable_outbox_payload_bytes | 262144 | 0 |
| max_attempts_per_target_per_cycle | 8 | 8 |
| max_cancel_attempts_per_transaction | 1 | 1 |
| max_evidence_per_target | 8 | 8 |
| max_retained_terminal_transactions | 2048 | 64 |
| max_nonterminal_deliveries | 32 | 32 |
| max_event_spool_count | 0 | 32 |
| max_event_spool_bytes | 0 | 32768 |
| max_result_cache_entries | 64 | 64 |
| max_retained_dispositions | 64 | 64 |
| max_ingress_per_step | 64 | 64 |
| max_callbacks_per_step | 64 | 64 |
| max_state_transitions_per_step | 64 | 64 |
| max_bearer_sends_per_step | 64 | 64 |
| max_deferred_tokens | 32 | 32 |

Accepted range/zero matrix（上表maxとのinclusive range）:

| Field | Controller | Endpoint |
| --- | --- | --- |
| max_services | 1..16 | 1..8 |
| max_nonterminal_transactions | 1..256 | 1..32 |
| max_targets_per_transaction | exactly 1 | exactly 1 |
| max_logical_payload_bytes | 1..1024 | 1..1024 |
| max_durable_outbox_payload_bytes | 1..262144 | exactly 0 |
| max_attempts_per_target_per_cycle | exactly 8 | exactly 8 |
| max_cancel_attempts_per_transaction | exactly 1 | exactly 1 |
| max_evidence_per_target | 1..8 | 1..8 |
| max_retained_terminal_transactions | 1..2048 | 1..64 |
| max_nonterminal_deliveries | 1..32 | 1..32 |
| max_event_spool_count | exactly 0 | 0..32 |
| max_event_spool_bytes | exactly 0 | count=0ならexactly 0、count>0なら2560..32768 |
| max_result_cache_entries | 1..64 | 1..64 |
| max_retained_dispositions | 1..64 | 1..64 |
| max_ingress_per_step | 1..64 | 1..64 |
| max_callbacks_per_step | 1..64 | 1..64 |
| max_state_transitions_per_step | 2..64 | 2..64 |
| max_bearer_sends_per_step | 1..64 | 1..64 |
| max_deferred_tokens | 1..32 | 1..32 |

規則:

- Callerは全fieldを明示します。0を「default」と解釈しません。
- `storage_namespace`はtext/pathではないopaque bytesで、lengthはinclusive `1..255`です。length 0、256以上、`length > 0 && data == NULL`、`length == 0 && data != NULL`は`ninlil_runtime_create() = NINLIL_E_INVALID_ARGUMENT`、`*out_runtime = NULL`です。NUL終端、UTF-8、Unicode normalization、case folding、path separatorの意味を与えず、embedded NULとnon-UTF-8 byteを含む全byte値を許します。Namespace identity/equalityは`uint32 length + exact byte sequence`だけです。
- `config`と`config.storage_namespace.data`はruntime_create call中だけborrowedです。Coreは全validation後、Storage `open`より前にexact length bytesをAllocatorでdeep-copyし、そのRuntimeが成功した場合は`runtime_destroy`完了まで所有します。Callerはruntime_create return後に元bufferを変更・解放できます。Copy allocation failureは`NINLIL_E_CAPACITY_EXHAUSTED`、runtime NULLで、Storage `open`を呼びません。
- Storage `open`へ渡す`ninlil_bytes_view_t`はcopy済みnamespaceの同じlengthとexact bytesです。Storage Portにはopen call中だけborrowedで、pointer identityやNUL終端へ依存せず、必要ならhandleへ自らcopyします。runtime_createが後で失敗した場合も、CoreはStorage handleをcloseしてcopyをexactly 1回deallocateします。成功時はruntime_destroyでStorage close後にcopyをexactly 1回deallocateします。
- `runtime_id`はnon-zero、`local_identity`は3.1のpresence規則を満たします。送信source partyはこのruntime ID/local identityと登録serviceの`local_application_instance_id`から構成し、caller submissionに自己申告source fieldを持たせません。
- 上表で0を含むfieldだけ0を指定できます。0をdefault/unbounded/disabledの暗黙値へ読み替えません。Range未満/conditional zero違反は`runtime_create = NINLIL_E_INVALID_ARGUMENT`、named profile上限超過は`NINLIL_E_UNSUPPORTED`です。別のlarger named profileはM1aにありません。
- `max_targets_per_transaction == 1`、`max_attempts_per_target_per_cycle == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE`です。M1aで小さくして保証を変えたり、大きくしてcycleを延長しません。
- `max_cancel_attempts_per_transaction == 1`です。0または2以上を設定せず、Command admissionはremote cancel record/attempt 1件分をlocal reservationへ含めます。
- Cross-fieldは`max_deferred_tokens <= max_nonterminal_deliveries <= max_nonterminal_transactions`、`max_event_spool_count <= max_nonterminal_transactions`、Controllerでは`max_durable_outbox_payload_bytes >= max_logical_payload_bytes`です。全比較/加算はcheckedで、違反/overflowは`NINLIL_E_INVALID_ARGUMENT`です。Endpoint event count>0はmanagement reservation 2560 bytes以上を要求しますが、payload/attempt capacityは各admissionで残量検査し、count limitまで必ず同時収容できる保証にはしません。
- `terminal_retention_ms`は1..`NINLIL_M1A_MAX_RETENTION_MS`、`result_cache_retention_ms`は1..terminal retention、`observation_retention_ms`は0..`NINLIL_M1A_MAX_RETENTION_MS`です。範囲外は`NINLIL_E_INVALID_ARGUMENT`です。Foundation Simulator fixtureはterminal/result cache 86400000ms、observation 3600000msを明示し、0をdefaultにしません。
- EventFactはrequired Receiptまたはexplicit discardまでretention対象外で、削除禁止です。

Stage 1 validationの分類precedenceはclosedで、`top-level config/platform pointer` → `config/platform outer ABI header/size` → `inline config headerとplatform sub-vtable pointer` → `platform sub-vtable ABI header/size` → `required function pointer` → `reserved/unknown numeric enum` → `named unsupported role/environment` → `runtime ID/local identity/namespace shape` → `lower/conditional/cross-field/retention` → `checked derivation overflow` → `named profile upper`の順です。Pointer/function欠落は`NINLIL_E_INVALID_ARGUMENT`、ABI header/size違反は`NINLIL_E_ABI_MISMATCH`、それ以降はclosed tableの`NINLIL_E_INVALID_ARGUMENT`または`NINLIL_E_UNSUPPORTED`へ正規化し、後順位の違反で先順位を上書きしません。Outer ABI headerが有効になるまでnested pointer/fieldをreadしません。Supported createはController/EndpointかつTESTだけです。PlatformはroleによらずAllocator、Execution、Clock、Entropy、Storage、Bearer、Tx Gate、Origin Authorizationの8 sub-vtableと、各required function pointerをすべて要求します。各sub-vtableの`user`はNULLでもvalidです。

Capacity limitはaccepted configから`N = max_nonterminal_transactions + max_retained_terminal_transactions`として、kind 1..11を順に`max_services`、`N`、`N * max_targets_per_transaction`、`max_durable_outbox_payload_bytes`、`max_nonterminal_deliveries`、`max_event_spool_count`、`max_event_spool_bytes`、`max_result_cache_entries + max_retained_dispositions`、`N * max_targets_per_transaction * (uint64(max_evidence_per_target) + 1)`、`max_ingress_per_step`、`max_deferred_tokens`へ導出します。全加算/乗算は`uint64_t` checked arithmeticで、1件でもoverflowしたら`NINLIL_E_INVALID_ARGUMENT`、partial limit publish 0です。Roleで不使用のkindもzero entryを残します。

### 6.1 Runtime create lifecycle

`ninlil_runtime_create()`は次のstageをexact orderで実行します。`*out_runtime`はrequired pointer validation直後にNULL化し、stage 9までpublishしません。Earlier stage failureではlater stage/Portを呼びません。

| Stage | Required work | Failure/public effect |
| ---: | --- | --- |
| 1 | runtime config、platform aggregate、全nested ABI header/size/reserved/enum/range/null、全required vtable/function pointerをpure validation | API mismatch/invalid/unsupported。Allocator/Execution/Storage/Bearer/Clock/Entropy call 0 |
| 2 | `execution.current_context_id(user)`を1回callしnon-zero owner contextをcapture | 0なら`NINLIL_E_DEGRADED`。他Port call 0 |
| 3 | Core state、vtable/config scalar copy、namespace exact deep-copy、profile-bounded tablesをAllocatorで確保 | 最初のNULLで`NINLIL_E_CAPACITY_EXHAUSTED`。取得済みallocationをreverse orderでexactly once free |
| 4 | `storage.open(user, copied_namespace, NINLIL_STORAGE_SCHEMA_M1A, &handle)`をexactly 1回 | 下表mapping。FailureはStorage handleがあればclose後deallocate |
| 5 | Storage schema/profile binding、commit-unknown resolution、recovery scan/fence、persistent capacity metadataを完了 | Existing incompatible profile=`NINLIL_E_UNSUPPORTED`。Storage mapping/unknownは下表。Recovery未完了でBearerをopenしない |
| 6 | `bearer.open(user, runtime_id, role, &handle)`をexactly 1回。M1aはlazy openしない | 下表mapping。FailureはBearer handleがあればclose、次にStorage close、deallocate |
| 7 | `clock.now`を1回取得し、trusted sampleをmetrics startへ固定。`clock_epoch_id`はnon-zero required、`now_ms == 0`はvalid。[17章](17-foundation-domain-store.md) CLOCK_BASELINEと比較・FULL更新 | temporary/UNCERTAIN=`NINLIL_E_CLOCK_UNCERTAIN`、permanent、trusted+全zero epoch、invalid trust enum、same-epoch regression=`NINLIL_E_DEGRADED`。Baseline COMMIT_UNKNOWNはnamespace fence、publish 0 |
| 8 | metrics epoch IDを§5.2の最大4 entropy call/partial/all-zero規則で取得。Collision checkなし | 4 candidates失敗=`NINLIL_E_ENTROPY`。reverse cleanup。Transaction/attempt entropyは消費しない |
| 9 | Stage 5で再構成したdurable health causesを固定priorityへprojectし、cleanなら`OK/NONE`、残存causeありなら`DEGRADED/exact reason`。metrics zero counters/start sample/epoch ID、owner context、Port handlesをfinalizeし`*out_runtime`へ1回publish | `NINLIL_OK`。DEGRADED healthはcreate API failureではない。この時点からcallerがruntimeを所有 |

Stage 5の0/17 bootstrap/domain判定は0-byte prefix iteratorとcaller-owned key 255/value 4096-byte workspaceを使います。Private namespaceはfuture rootを含めsingle value 4096 bytes以下がcontractで、required key>255またはvalue>4096の`BUFFER_TOO_SMALL`はbytesを推測せず`NINLIL_E_STORAGE_CORRUPT`です。65,536-byte temporary allocation、ESP32 task stack上のrecord buffer、keyだけの採用は行いません。

Create/recovery Storage status mapping:

| Storage status | Public status |
| --- | --- |
| `OK` | continue |
| `BUSY` | `NINLIL_E_WOULD_BLOCK` |
| `NO_SPACE` | `NINLIL_E_CAPACITY_EXHAUSTED` |
| `IO_ERROR` | `NINLIL_E_STORAGE` |
| `CORRUPT`、unexpected `NOT_FOUND`/`BUFFER_TOO_SMALL` | `NINLIL_E_STORAGE_CORRUPT` |
| `UNSUPPORTED_SCHEMA` | `NINLIL_E_UNSUPPORTED` |
| `COMMIT_UNKNOWN` | `NINLIL_E_STORAGE_COMMIT_UNKNOWN`。namespaceをfenceしてcloseし、次createでauthoritative journal recovery |

Storage `open`はstatusより先にstatus/handle shapeを検査します。`OK + non-NULL`だけが継続、`OK + NULL`は`NINLIL_E_STORAGE_CORRUPT`です。Known non-OK + NULLは上表へmappingします。Non-OK + non-NULLはhandleをexactly once closeしてshape faultを優先し`NINLIL_E_STORAGE_CORRUPT`、unknown statusも同statusとし、handleがあればexactly once closeします。

Bearer open status mapping:

| Bearer status / output | Public status |
| --- | --- |
| `OK` + non-NULL handle | continue |
| `WOULD_BLOCK` / `UNAVAILABLE` | `NINLIL_E_WOULD_BLOCK` |
| `DENIED` | `NINLIL_E_UNSUPPORTED` |
| `EMPTY` / `LOST_UNKNOWN` / `CORRUPT` / `OK`だがNULL handle | `NINLIL_E_DEGRADED` |

Bearer `open`は`OK + non-NULL`だけが継続です。Known non-OK + NULLは上表へmappingします。Non-OK + non-NULLまたはunknown statusはunexpected handleがあればexactly once closeし、shape faultを優先して`NINLIL_E_DEGRADED`です。

Stage 7のpure clock mapperはcurrent ABI headerを設定し、残りをzero初期化したsampleを入力bufferにします。`OK + trusted + non-zero epoch`だけが継続し、`UNCERTAIN`または`TEMPORARY + exact unchanged buffer`は`NINLIL_E_CLOCK_UNCERTAIN`、`PERMANENT + exact unchanged buffer`とunknown status/non-OK poison/partial header/zero epoch/unknown trust/reservedは`NINLIL_E_DEGRADED`です。Pure helperはPort/harnessが与えるoptional external baselineを受け取り、同epochで`now_ms < baseline_now_ms`だけをregressionとして`NINLIL_E_DEGRADED`にできます。Production source/update境界は[17章](17-foundation-domain-store.md)のCLOCK_BASELINEです。D1 codecとRuntime接続前はhelper testだけでCR8 completeと扱いません。

Stage 8は最大4回`entropy.fill(16)`を観測し、`OK + 16-byte non-zero candidate`を即採用します。直前createと同値でもcollision checkしません。All-zero、TEMPORARY/PERMANENT/unknown status、non-OK時のpartial bytesはfailed candidateとして次へ進み、4回失敗で`NINLIL_E_ENTROPY`です。Port contract上、Coreは`OK`で返った16-byte bufferがpartial writeかを推定せず、non-zeroなら受理します。

Stage 4以降のcleanup orderは、存在する場合だけ`bearer.close` → live Storage transaction/iterator 0を確認 → `storage.close` → service/table/namespace/runtime allocationsのreverse deallocateです。Close/deallocateは元failure statusを上書きせず、Port `user`を解放しません。Origin authorizationとTx Gateはcreate中にcallしません。複数faultをscriptしてもexact sequenceで最初に観測したfailureだけを返し、later fault pointへ到達しません。

Stage 5のnamespace profile bindingは次のclosed field setだけをversioned recordとして保持します。

| Binding field | Comparison |
| --- | --- |
| binding format / named profile | unsigned `format_version = 1` / exact ASCII `NINLIL-FOUNDATION-SMALL-1` |
| storage schema | `NINLIL_STORAGE_SCHEMA_M1A` exact |
| Runtime role / environment | unsigned enum value exact |
| Runtime ID | 16 bytes exact、non-zero |
| resource limits | `ninlil_resource_limits_t`の19 scalarを宣言順にunsigned value exact |
| retention | terminal / result-cache / observationの3 ms値 exact |

比較はC struct memory、padding、pointer、hashに依存せず、上表のtyped fieldを順に比較します。`storage_namespace`はrecord keyでありvalueへ重複保存せず、`local_identity`はimmutable profile binding fieldではなく、別のversioned current-identity recordです。Runtime IDを変える場合は別storage namespaceが必要です。

Current local identityは初回createでpersistし、recreateでは次のclosed forward-rotation ruleをStage 5/Bearer open前に適用します。

- Device presence flagとdevice IDはnamespace owner anchorとしてexact不変です。
- Installation presence/IDと`binding_epoch`が全てexactならno writeです。いずれかが変わる場合はnew `binding_epoch > stored binding_epoch`がrequiredです。
- Site presence/IDと`membership_epoch`が全てexactならno writeです。いずれかが変わる場合はnew `membership_epoch > stored membership_epoch`がrequiredです。Presence規則によりsite removalでepoch 0へ戻すrotationはM1aでは不可、new siteへ直接higher epochで移ります。
- Device anchor mismatch、equal/regressive epochでtuple変更は`NINLIL_E_CONFLICT`、durable state不変、Bearer open 0です。Forward rotationはcurrent identityだけを1 FULL commitし、failure/unknownは通常Storage mapping/namespace fenceです。

Forward rotation後は新規admission/inbound bindingだけがnew current snapshotを使い、既存transaction、Delivery、grant、canonical digest、quota key/counterをrewrite/resetしません。

空namespaceの初回createはprofile binding、capacity metadata初期値、`transaction_sequence=0`、`last_assigned_ordered_input_sequence=0`、`last_assigned_scheduler_owner_sequence=0`、`last_visited_scheduler_owner_sequence=0`を1つの`FULL` transactionへcommitします。Commit unknownは`NINLIL_E_STORAGE_COMMIT_UNKNOWN`としてnamespaceをfenceし、次createのjournal recoveryで「全て存在」または「全て不在」へ収束させます。Reopenは4 counter/cursorをexact loadし、部分欠損、owner/indexより小さいassigned値、0 owner、MAX wrap痕跡をstorage corruptionとします。Existing profile recordが上表とexact matchなら再利用し、1 fieldでも違えば`NINLIL_E_UNSUPPORTED`でrecord/capacity/recovery stateを変更せずBearerをopenしません。Unknown future binding field/versionもsilent ignoreせず`NINLIL_E_UNSUPPORTED`です。

### 6.2 Private Runtime Store v1

Runtime Storeはpublic ABIを増やさないCore-private形式です。Key/valueはC struct memory、padding、pointer、host endianへ依存せず、全integerをunsigned big-endianでencodeします。Private key rootはexact 8 bytes `4e 49 4e 4c 49 4c 00 01`（ASCII `NINLIL`、zero、keyspace version 1）です。

L2a private codec APIのinput/output object・byte rangeはexact/partialを問わず相互にoverlapしてはなりません。Overlapまたはrange終端のaddress加算overflowは`NINLIL_E_INVALID_ARGUMENT`で、いずれのrangeも変更しません。Generic envelope decodeのpayload viewはencoded inputをborrowし、そのinputの生存期間を越えて保持しません。

| Record | Exact key bytes | Value type |
| --- | --- | ---: |
| profile binding | `4e494e4c494c0001 01` | 1 |
| current identity | `4e494e4c494c0001 02` | 2 |
| counter/cursor | `4e494e4c494c0001 03 kk`、`kk=01..04` | 3 |
| capacity metadata | `4e494e4c494c0001 04 kk`、`kk=01..0b` | 4 |

Counter kindは1=`transaction_sequence`、2=`last_assigned_ordered_input_sequence`、3=`last_assigned_scheduler_owner_sequence`、4=`last_visited_scheduler_owner_sequence`です。Capacity kindはpublic resource kind 1..11とexact一致します。Family 5はstandalone internal-invariant health source、family 6はdomain record/operation witnessです。Exact key/value、chunk、backlink、retention、相互validation、capacity contributionの正本は[17章](17-foundation-domain-store.md)です。L2a bootstrapはfamily 5/6を生成せず、D1 codec/D2 scanner/D3 validation未完了の間はStage 5や汎用COMMIT_UNKNOWN recoveryを完成扱いしません。

全valueは次のclosed envelopeです。

```text
magic          4 bytes exact 4e 4c 52 31  # ASCII NLR1
record_type    u16 big-endian
record_version u16 big-endian, exact 1
payload_length u32 big-endian
payload        exact payload_length bytes
checksum       u32 big-endian CRC32C
```

Total lengthはexact `12 + payload_length + 4`で、trailing byteを許しません。CRC32CはCastagnoli reflected polynomial `0x82f63b78`、initial/final XOR `0xffffffff`で、checksum fieldを除くenvelope先頭からpayload末尾までを入力にします。ASCII `123456789`のgolden checksumは`0xe3069283`です。Key familyと`record_type`は一致必須です。Current keyspaceでmagic/type/length/checksum、boolean、reserved invariantが不正なら`NINLIL_E_STORAGE_CORRUPT`、current exact keyのunknown `record_version`は`NINLIL_E_UNSUPPORTED`です。Checksumはsecurity/authenticationではなくportable corruption detectionであり、Storage Portのdurability/integrity契約を置き換えません。

Payloadは次のfieldだけをexact order/widthで持ちます。

- Type 1 profile binding、payload 167 bytes: `binding_format:u32=1`、`profile_name_length:u16=25`、exact 25-byte ASCII `NINLIL-FOUNDATION-SMALL-1`、`storage_schema:u32`、`role:u32`、`environment:u32`、`runtime_id[16]`、resource limit 19 scalarをABI宣言順かつABIのunsigned width（`max_durable_outbox_payload_bytes`と`max_event_spool_bytes`だけu64、他はu32）、terminal/result-cache/observation retentionを各u64でencodeします。Value totalは183 bytesです。ABI header、reserved field、namespace、paddingは保存しません。
- Type 2 current identity、payload 68 bytes: `flags:u32`、device/installation/site IDを各16 bytes、`binding_epoch:u64`、`membership_epoch:u64`です。Value totalは84 bytesです。Known flagだけ、presenceとzero/non-zero ID/epochの3.1規則を要求します。
- Type 3 counter/cursor、payload 16 bytes: `counter_kind:u32`、`value:u64`、`exhausted_marker:u32`です。Value totalは32 bytesです。Kindはkey suffixと一致し、markerはexact 0/1、kind 4では0必須です。Kind 1..3のmarker 1はvalue `UINT64_MAX`を要求しますが、value MAXだけでmarker 1を推測しません。Initial value/markerは全kind 0です。Live owner/indexとの大小、orphan、wrap痕跡の相互validationはL2b domain recovery scanで行い、codec単体の成功条件へ偽装しません。
- Type 4 capacity metadata、payload 52 bytes: `resource_kind:u32`、`limit:u64`、`used:u64`、`reserved:u64`、`high_water:u64`、`capacity_epoch:u64`、`blocked:u32`、`counter_exhausted:u32`です。Value totalは68 bytesです。Kindはkey suffix、limitはprofileからのchecked derivationとexact一致し、booleanはexact 0/1、epochはnon-zero、checked `used + reserved <= high_water <= limit`です。`counter_exhausted=1`はepoch MAXかつblocked 0を要求しますが、epoch MAXだけでmarkerを推測しません。Initialは11 kindすべてused/reserved/high-water 0、epoch 1、blocked/exhausted 0で、role非使用kindもrecordを省略しません。

Initial bootstrap groupはprofile 1、identity 1、counter 4、capacity 11のexact 17 recordsです。上記codecではencoded key+valueがexact 1,311 bytes、Storage portable usageがexact 17 entries / 1,583 logical bytes（`16 + key_length + value_length`）です。17 recordsをkey unsigned-byte lexicographic順にstageし、`runtime.before_namespace_binding_commit`後に1回だけ`commit(FULL)`します。Commit OK後だけ`runtime.after_namespace_binding_commit`へ到達します。Initial identityはこのHC13 groupに含め、identity-rotation hook occurrenceは0です。

同一read snapshotで17/17 presentはexisting、0/17かつnamespace全体にkey 0件だけをnew、1..16/17は`NINLIL_E_STORAGE_CORRUPT`と分類します。0/17でもcurrent keyspaceの別keyまたはunrecognized private dataがあればemptyとみなさずcorrupt、recognizable future keyspace/profile versionは`NINLIL_E_UNSUPPORTED`です。Envelope integrityと17-record completenessをprofile compatibilityより先に検査します。Profile exact mismatchは`NINLIL_E_UNSUPPORTED`、write/recovery mutation/Bearer open 0です。

Initial commitが`COMMIT_UNKNOWN`ならsame transactionをretryせずStorageをclose/fenceし、`NINLIL_E_STORAGE_COMMIT_UNKNOWN`を返します。次createは同一snapshotの17/17をcommitted truth、0/17かつemptyをnon-committed truthとしてauthoritativeに扱い、partialをcorruptにします。Current identity rotationはsingle Type 2 replacementなので、unknown後のold/new exact valueがauthoritative truthです。Bootstrap/identity以外のmulti-record business operationは[17章](17-foundation-domain-store.md)のwitnessによりall-old/all-newへ収束します。

L2aはkey builder、envelope/profile/identity/counter/capacity codec、CRC、17-record presence classification、profile compare、identity forward-rotation判定だけを行うpure modelで、Storage Port callとRuntime bodyを持ちません。L2bはStorage open、single-snapshot load、FULL bootstrap、Stage 5 journal/domain recovery、counter/capacity相互validation、durable health-source scan、identity rotation、cleanup/status mappingを担当します。Clock durable baselineは[17章](17-foundation-domain-store.md)family 6 subtype 62としてD1以降に実装します。

L2a2 encoded snapshotの`values[i]`はexact `key_id=i+1`へ対応し、17 viewとそのbyteはvalidation call中だけborrowされます。Validated snapshotは17件すべてのtyped integrity成功後にだけ生成され、profile/identity decisionはこのprovenanceを持つ型だけをstored側入力にします。Compact planはStage1 successが発行したheader/pointer/reserved無しaccepted-config projectionだけから生成し、success後はimmutableです。`record_at`はplanをcall中borrowし、caller-owned単一scratchへ1 recordを生成します。Scratch lifetimeはそのStorage `put` returnまでで、`put: OK`のdeep-copy後に直ちに再利用できます。全object/view byte rangeはpairwise non-overlapで、alias/address overflowは全range不変の`NINLIL_E_INVALID_ARGUMENT`、non-alias failureはoutput all-zeroです。

Existing snapshotを17 encoded valueとvalidated projectionの両方で同時常駐させるか、incremental validationへ縮小するかはL2bのbounded Runtime-owned memory region設計で固定します。L2a2のhost-side aggregate型をそのままESP stackへ置くことは決定していません。Production-private target分離はL2b開始前の必須gateです。

## 7. Service Descriptorとcallback

### 7.1 Descriptor

```c
typedef struct ninlil_service_descriptor {
    NINLIL_STRUCT_HEADER;
    ninlil_bytes_view_t namespace_id;
    ninlil_bytes_view_t service_id;
    ninlil_bytes_view_t schema_id;
    uint64_t descriptor_revision;
    ninlil_digest256_t descriptor_digest;
    ninlil_id128_t local_application_instance_id;
    uint16_t schema_major;
    uint16_t schema_minor_min;
    uint16_t schema_minor_max;
    uint16_t reserved_zero_u16;
    ninlil_family_t family;
    ninlil_direction_t direction;
    ninlil_admission_authority_t admission_authority;
    ninlil_apply_contract_t apply_contract;
    ninlil_custody_policy_t custody_policy;
    uint32_t supported_evidence_mask;
    uint32_t logical_payload_limit;
    uint32_t target_limit;
    uint32_t inflight_limit;
    uint32_t max_attempts_per_target_per_cycle;
    uint32_t admission_window_ms;
    uint32_t max_admissions_per_window;
    uint32_t max_payload_bytes_per_window;
    uint32_t reserved_zero_u32;
    uint64_t minimum_deadline_ms;
    uint64_t maximum_deadline_ms;
    uint64_t maximum_evidence_grace_ms;
    uint64_t attempt_receipt_timeout_ms;
    uint64_t retry_backoff_ms;
    uint64_t application_completion_timeout_ms;
    uint64_t required_dedup_window_ms;
} ninlil_service_descriptor_t;
```

Descriptor validation:

- namespace/service/schema、revision、digest、local application IDはrequiredです。
- `schema_minor_min <= schema_minor_max`です。
- descriptor digestは外部manifest/compilerが供給するimmutable SHA-256です。M1a Runtimeはnon-zeroとalgorithmだけを検査します。
- 同一namespace+service+revisionの再登録は、全contract fieldとdescriptor digestが同じ場合だけidempotentです。
- `local_application_instance_id`とcallback/userはdescriptor digestの対象外ですが、同一Runtimeでの再登録時はlocal application ID、両function pointer値、user pointer値がexact一致必須です。callbacks struct自体のaddressは比較しません。
- Exact再登録成功は`NINLIL_OK`で、最初の登録が返した**同じ`ninlil_service_t *` pointer value**を返します。alias handle、new allocation、SERVICE used/reserved/high-water増加、descriptor/callback/user copyの置換、registration順変更を行いません。Callerが一時callbacks structを別addressで再構成しても、そのfield値がexactなら同じhandleです。
- 同じnamespace+service+revisionだが上記contract/local application/function/user valueのどれかが異なるvalid再登録は`NINLIL_E_CONFLICT`、`*out_service = NULL`です。既存handle/state/capacityを変更しません。Callback shape自体がinvalidな場合はlookupより先に7.1の`NINLIL_E_INVALID_ARGUMENT`です。
- M1aはdescriptor `target_limit == 1`かつruntime `max_targets_per_transaction == 1`だけを受理します。一般にdescriptorのpayload、target、inflight、attempt、evidence等のhard limitがruntime resource profileを超える場合、`service_register`は`NINLIL_E_UNSUPPORTED`です。
- `logical_payload_limit`、`inflight_limit`、`admission_window_ms`、`max_admissions_per_window`、`max_payload_bytes_per_window`、`required_dedup_window_ms`はnon-zeroです。`admission_window_ms`は1..`NINLIL_M1A_MAX_RETRY_DELAY_MS`、`max_payload_bytes_per_window >= logical_payload_limit`です。違反は`NINLIL_E_INVALID_ARGUMENT`です。
- `supported_evidence_mask`は両M1a familyとも`RECEIVED`、`DURABLY_RECORDED`、`APPLIED`、`VERIFIED`の4 known bitから成るnon-empty subsetです。bit 0 (`NONE`)またはreserved bitを含むdescriptorは`NINLIL_E_INVALID_ARGUMENT`です。M1aにfamily別の追加mask制限はなく、required evidenceはこのdescriptor maskに含まれるexactly 1 non-zero stageをSubmissionが選びます。Receiverは各stageのsemantic factを実際に成立・durably記録した場合だけそのstageをReceiptとして発行し、単にmaskでadvertiseしたことを証拠の成立と扱いません。
- admission fixed windowは`floor(now_ms / admission_window_ms)`です。admit count/bytesはadmissionと同じFULL transactionで更新します。
- DesiredStateは`1 <= minimum_deadline_ms <= maximum_deadline_ms < NINLIL_NO_DEADLINE`です。Submission deadlineはこのinclusive range、graceは`0 <= evidence_grace_ms <= maximum_evidence_grace_ms`で、checked `admitted_at + deadline + grace`がrepresentableでなければ`DEADLINE_INVALID` rejectionです。
- EventFactは`minimum_deadline_ms == maximum_deadline_ms == NINLIL_NO_DEADLINE`かつ`maximum_evidence_grace_ms == 0`です。
- EventFactは`max_attempts_per_target_per_cycle == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE`です。
- DesiredStateはfinite deadlineです。`NINLIL_NO_DEADLINE`を許しません。
- `attempt_receipt_timeout_ms`は各send attemptがReceipt/Dispositionを待つ時間で、両familyとも1〜`NINLIL_M1A_MAX_ATTEMPT_RECEIPT_TIMEOUT_MS`です。EventFactのno-deadlineを置き換えるものではありません。
- `retry_backoff_ms`はretryable failure後の固定backoffで、両familyとも1〜`NINLIL_M1A_MAX_RETRY_BACKOFF_MS`です。M1aはexponential backoffとjitterを実装しません。
- `application_completion_timeout_ms`は1〜`NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS`です。0はinvalid descriptorです。
- `maximum_evidence_grace_ms`はDesiredStateのeffect deadline後にlate evidenceを待つ上限であり、attempt Receipt timeoutやapplication completion timeoutとは別です。EventFactでは0です。
- `terminal_retention_ms`と`result_cache_retention_ms`のどちらかが`required_dedup_window_ms`未満なら`ninlil_service_register()`は`NINLIL_E_UNSUPPORTED`です。sender/receiverの別にかかわらず、idempotency mapping、terminal query record、remote result cacheが要求windowより早く消える構成を受理しません。

#### Admission quota semantics

Descriptorのinflight/count/byte quotaはlocal senderからの**新規origin admission**だけへ適用し、receiver ingress/Delivery、retry、resume、ALREADY_ADMITTEDには適用しません。Quota keyはstorage namespaceを外側scopeとし、`local_application_instance_id + namespace_id exact bytes + service_id exact bytes + descriptor_revision + descriptor_digest`のexact tupleです。Runtime IDとlocal identityはkeyへ含めず、Runtime recreateやforward identity rotationでcounterをresetしません。

- `inflight_count`は同quota keyでFULL admission commit済み、かつ最初のterminal Outcome FULL commitが未成立なorigin transaction数です。Admission commitでchecked +1、最初のterminal commitでchecked -1をそのstate changeと同じFULL transactionへ含めます。Retained terminal transactionは数えません。Underflow/missing quota recordはstorage corruptionです。
- Fixed-window keyは`admission_clock_epoch_id + floor(admission_reference_now_ms / admission_window_ms)`です。`current_window_started_at_ms = now_ms - (now_ms % admission_window_ms)`。Quota keyごとにpersistするcurrent bucketはexactly 1件だけです。異なるepoch/window keyを観測したrequestはcurrent count/bytes 0として評価し、admission成功の同じFULL transactionでold bucketをnew key/count/bytesへatomic overwriteします。Rejection/API errorではold bucketを変更せず、次requestも論理current値0として評価します。長期稼働でold bucket履歴を追加保存しません。
- `admissions_in_window`は新規FULL admission 1件につき1、`payload_bytes_in_window`はSubmissionのexact logical `payload.length`だけをchecked加算します。Event management 2,560 bytes、envelope、attempt、retry、Storage overheadは数えません。
- Idempotent replay、conflict、rejection、API error、definite commit failureはcounterを変更しません。Admission COMMIT_UNKNOWNはtransaction/mapping/reservation/quotaが全部commitまたは全部non-commitだけです。Terminal COMMIT_UNKNOWNはauthoritative recoveryまでinflightを解放済みと推測しません。

Provider normal DENYはtransaction/scheduler owner counter headroomより後、Core quota/resource prospective guardより先にそのexact tupleで終了します。Valid ALLOW（Commandはproviderなし）後の単一guard precedenceは次表の上から下です。Prospective値を評価し、同じFULL admission commitへservice counter/bucket updateを含めます。複数同時違反でも最初の1 reasonだけを返します。

| Order / exhausted guard | Submission kind / reason | Guidance / relative delay |
| --- | --- | --- |
| 1. service `inflight_count + 1 > inflight_limit` | `REJECTED / CAPACITY_EXHAUSTED` | `RETRY_SAME_AFTER / 0` |
| 2. service `admissions_in_window + 1 > descriptor.max_admissions_per_window` | `REJECTED / RATE_EXHAUSTED` | `RETRY_SAME_AFTER / admission_window_ms - (now_ms % admission_window_ms)` |
| 3. service `payload_bytes_in_window + payload.length > descriptor.max_payload_bytes_per_window` | `REJECTED / RATE_EXHAUSTED` | count rowと同じexact remaining delay |
| 4. Event `payload.length > decision.max_payload_bytes` | `REJECTED / GRANT_LIMIT_EXCEEDED` | `RETRY_SAME_AFTER / 0` |
| 5. Event `active_spool_count + 1 > decision.max_active_spool_count` | `REJECTED / GRANT_LIMIT_EXCEEDED` | `RETRY_SAME_AFTER / 0` |
| 6. Event `active_spool_bytes + payload.length + 2560 > decision.max_active_spool_bytes` | `REJECTED / GRANT_LIMIT_EXCEEDED` | `RETRY_SAME_AFTER / 0` |
| 7. Event `admissions_in_window + 1 > decision.max_admissions_per_window` | `REJECTED / RATE_EXHAUSTED` | descriptor window remaining |
| 8. Runtime resource reservation不足 | `REJECTED / CAPACITY_EXHAUSTED` | `RETRY_SAME_AFTER / 0` |

全prospective加算はcheckedです。Overflowはそのguardを「limit超過」として同じreason/delayへfail closedし、wrapしません。Boundaryはinclusiveで、prospective値がlimit exactならadmitできます。Rejected resultのID/digest/assuranceは§8のall-field matrixどおりzeroです。Clock sample/epochがtrustedでない場合はquotaを数値比較せず既存clock error pathを使います。

Role × family registration/submit matrixは次の4行だけです。local sideはRuntime role、family、family固有directionからCoreが導出し、callerがsender/receiverを別fieldで指定することはありません。

| Runtime role | Family / required descriptor direction | Local side | Required callback shape at `service_register` | `ninlil_submit` |
| --- | --- | --- | --- | --- |
| `CONTROLLER` | DesiredStateCommand / `DOWNLINK + CONTROLLER_ONLY` | Command sender | `on_delivery == NULL`かつ`on_reconcile == NULL` | allowed |
| `ENDPOINT` | DesiredStateCommand / `DOWNLINK + CONTROLLER_ONLY` | Command receiver | `on_delivery != NULL`。`APPLICATION_DEDUP`なら`on_reconcile != NULL`、`IDEMPOTENT`ならNULL可 | direction rejection |
| `ENDPOINT` | EventFact / `UPLINK + ORIGIN_WITH_GRANT` | Event sender | `on_delivery == NULL`かつ`on_reconcile == NULL` | allowed |
| `CONTROLLER` | EventFact / `UPLINK + ORIGIN_WITH_GRANT` | Event receiver | `on_delivery != NULL`かつ`on_reconcile != NULL` | direction rejection |

- Known familyだが4.2のfamily固有direction/admission authority/apply contractと一致しないdescriptorは、callback shapeを評価する前に`ninlil_service_register() = NINLIL_E_UNSUPPORTED`、`*out_service = NULL`です。Runtime roleと正しいdescriptorから導出したlocal sideに対してcallback shapeが上表と違う場合は`NINLIL_E_INVALID_ARGUMENT`、`*out_service = NULL`です。部分登録しません。
- EndpointでEvent sender serviceを登録するにはruntime profileの`max_event_spool_count > 0`かつ`max_event_spool_bytes >= NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES`が必要です。0/0のreceive-only EndpointへEvent senderを登録すると`NINLIL_E_UNSUPPORTED`、service NULLで、capacityを変更しません。

Service registrationはdurable semantic registryとRuntime-lifetime attachmentを分けます。

- 初回unique registrationはnamespace/service/revision key、全descriptor semantic field/digest、local application instance ID、required callback shapeをSERVICE slotと同じ`FULL` transactionへpersistし、commit OK後だけvolatile Service handleとcallback/function/user attachmentをpublishします。Function/user pointer値、callbacks struct address、Service handle pointerはpersistしません。
- 同じRuntime lifetime内のexact再登録は上記どおりfunction/user pointer値まで一致必須でsame handle/no writeです。Runtime recreate後の最初のattachはpersist済みsemantic registryだけを照合し、新processのvalid callback/function/user値を受理します。旧process pointer値との比較は禁止です。AttachはSERVICE used/high-waterを増やさずdurable write 0です。
- Persisted keyとsemantic descriptor/local application IDが違うsame namespace/service/revisionは`NINLIL_E_CONFLICT`、unknown/new revisionは別unique serviceとしてcapacityを使い初回registration手順へ進みます。Old pending recordをnew revision callbackへ渡しません。
- Stage 5はpersist済みservice registryとSERVICE used/high-waterをloadしますがattachment/handleは0件です。Exact serviceが再attachされるまで、そのserviceのpending origin dispatch、Delivery callback、reconcile、cached reverse sendを実行しません。`runtime_step`はそれらをrunnable workに数えずsend/callback 0、registration成功時にimmediate wakeをscheduleします。
- Unattached receiver serviceへのvalid inbound APPLICATIONはpersist済みdescriptorでbinding検証し、capacityがあればINBOX_COMMITTEDへdurable copyできますが、attachment前にcallback、CustodyAccepted、Receipt、Dispositionを送信しません。Capacityがなければ通常bounded ingress ruleです。
- First registration FULL commitのStorage error/unknownは通常mappingを返し、handle NULL、callback/user保持0、SERVICE reservation rollbackまたはall-or-none recoveryです。Recreate attachのvolatile allocation failureは`NINLIL_E_CAPACITY_EXHAUSTED`でdurable registryを変えません。
- Receiver handleへの構文的にvalidな`ninlil_submit()`はAPI invocation errorにせず、exactly `NINLIL_OK + NINLIL_SUBMISSION_REJECTED + NINLIL_REASON_UNSUPPORTED_DIRECTION + NINLIL_RETRY_MODIFIED + retry_delay_ms 0`を返します。transaction ID、canonical submission digest、assuranceはzeroで、entropy、authorization provider、reservation、storage writeを行いません。
- Sender handleへ届いたforward `APPLICATION`、またはReceiver handleへ届いたそのfamilyのreverse messageはwrong-direction ingressです。callback/reducerへ渡さず、5.4のinvalid-ingress diagnosticだけを記録し、Receipt/Dispositionで応答しません。

Attempt Receipt timeoutは両familyへ適用し、Bearer sendがaccepted/custody/LOST_UNKNOWNまたはCORRUPT/invalid possible-deliveryとなったobservation logical timeから`checked(send_observed_at_ms + attempt_receipt_timeout_ms)`で生成して同じattempt IDへbindします。Definitive no-sendでは生成しません。Timeoutと同じlogical timeですでにdurable ingressしたvalid Receipt/Dispositionを先にreduceします。

- Bearerがmessageを受理していないことを確定したstatusは12章5.5 closed matrixへ従います。WOULD_BLOCK/UNAVAILABLEは`NO_EFFECT_PROVEN`で、Commandだけfixed-backoff retry候補、EventはBEARER_UNAVAILABLE early parkです。DENIEDは`NO_EFFECT_PROVEN`ですがautomatic retryせず、CommandはFAILED_DEFINITIVE、EventはAPPLICATION_REMEDIATION parkです。いずれもReceipt timeoutを作りません。
- ACCEPTED、DURABLE_CUSTODY、`LOST_UNKNOWN`、CORRUPT/invalid possible-delivery後にevidence未達でtimeoutしたattemptは`EFFECT_POSSIBLE`です。DesiredStateはno-effect failureへ落とさずevidence/deadlineを保持し、apply contract、deadline、retry budgetがsafe retryを許す場合だけnew attemptを作ります。evidence closeまで不明ならOUTCOME_UNKNOWNです。
- EventFactは`EFFECT_POSSIBLE`でもevent ID dedup/custodyを維持してfixed backoff後に次attemptへ進み、cycle内`NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE` attempts後は`PARKED_RETRY`です。
- DesiredState effect deadline、EventFact retry cycle、evidence grace、application completion timeoutをattempt timeoutで代用しません。
- Current DesiredStateCommand attemptのReceipt timeout reducerがstate/effect certainty/timerを変更するFULL commitは`controller.before_command_attempt_timeout_commit` / `controller.after_command_attempt_timeout_commit`を通ります。stale old-attempt timeout、既にdurable ingress済みReceipt/Dispositionへ負けたtimeout、EventFact timeoutはこのpairを通りません。EventFactは§17の`endpoint.before_event_attempt_timeout_commit` / `after_event_attempt_timeout_commit`です。
- DesiredStateCommandの`evidence_close_at`でrequired evidence未達を`OUTCOME_UNKNOWN / EFFECT_POSSIBLE_EVIDENCE_MISSING`へterminalizeするFULL commitは`controller.before_evidence_close_commit` / `controller.after_evidence_close_commit`を通ります。EventFactにはevidence-close timerもこのhookも発生しません。

### 7.2 Delivery/Application result

```c
typedef struct ninlil_delivery_view {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t event_id;
    ninlil_party_t source;
    ninlil_concrete_target_t local_target;
    ninlil_service_identity_t service;
    ninlil_digest256_t content_digest;
    uint64_t generation;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    ninlil_evidence_stage_t required_evidence;
    uint64_t delivery_count;
    ninlil_bytes_view_t payload;
} ninlil_delivery_view_t;

typedef struct ninlil_application_result {
    NINLIL_STRUCT_HEADER;
    ninlil_application_result_kind_t kind;
    ninlil_evidence_stage_t evidence_stage;
    ninlil_disposition_t disposition;
    ninlil_reason_t reason;
    ninlil_effect_certainty_t effect_certainty;
    ninlil_retry_guidance_t retry_guidance;
    uint64_t retry_delay_ms;
    ninlil_bytes_view_t evidence;
} ninlil_application_result_t;

typedef struct ninlil_reconcile_view {
    NINLIL_STRUCT_HEADER;
    ninlil_delivery_view_t delivery;
    uint64_t delivery_started_at_ms;
    uint64_t prior_callback_invocations;
} ninlil_reconcile_view_t;

typedef ninlil_callback_action_t (*ninlil_on_delivery_fn)(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result);

typedef ninlil_reconcile_action_t (*ninlil_on_reconcile_fn)(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result);

typedef struct ninlil_service_callbacks {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_on_delivery_fn on_delivery;
    ninlil_on_reconcile_fn on_reconcile;
} ninlil_service_callbacks_t;
```

Callback contract:

- `ninlil_service_register()`の`callbacks` pointer/structはcall中だけborrowedです。Runtimeは登録成功を返す前に`user`と両function pointerの**値**をservice-owned stateへcopyし、callbacks structのaddressを保持しません。登録失敗ではいずれも保持しません。
- `callbacks.user`はNULL可で、NULL/non-NULLはcallback shape validationへ影響しません。Runtimeはcopyした同じ値を各callbackの第1引数へ渡します。Non-NULLの場合、pointeeはRuntime所有にならず、callerが`runtime_destroy()`完了まで有効かつcallbackから使用可能に保ちます。Copy済みfunction pointerのcall target/codeも同じ期間callableでなければなりません。M1aにservice unregisterはありません。
- Sender serviceでは両callbackがNULL required、Receiver serviceでは`on_delivery` requiredです。Role × familyごとのexact shapeは7.1のclosed matrixに従います。
- Receiverの`APPLY_APPLICATION_DEDUP`では`on_reconcile` requiredです。Senderのdescriptorが同じapply contractでもcallbackを登録しません。
- Receiverの`APPLY_IDEMPOTENT`では`on_reconcile`はNULL可で、incomplete deliveryをRuntimeがsafe idempotent recoveryとして再dispatchします。
- `token`、`delivery` / `reconcile_view`、その全nested view、`out_sync_result` / `out_known_result` pointerはcallback invocation中だけborrowedです。ApplicationはDEFER時に許可されたdelivery tokenの**値**以外を保持しません。
- Runtimeは各callback invocation直前にout resultの全byteをzeroにし、`abi_version = NINLIL_ABI_VERSION`、`struct_size = sizeof(ninlil_application_result_t)`を設定します。ApplicationはABI header/reserved byteを変更せず、`kind`、`evidence_stage`、`disposition`、`reason`、`effect_certainty`、`retry_guidance`、`retry_delay_ms`、`evidence`のsemantic fieldだけを書きます。Header変更またはnon-zero reserved byteは`CALLBACK_CONTRACT`です。
- `on_delivery`のout resultを読むのはreturn action `CALLBACK_COMPLETE`だけです。`CALLBACK_DEFER`、`CALLBACK_FATAL`、unknown actionではout result全体をignoreし、evidence viewをdereference/copyしません。`on_reconcile`のout resultを読むのは`RECONCILE_KNOWN_RESULT`だけで、`REDELIVER`、`RETRY_LATER`、`OUTCOME_UNKNOWN`、unknown actionでは同様にignoreします。
- COMPLETE/KNOWN_RESULTで使う`evidence`はApplication-owned borrowed bytesです。Applicationはcallback return handoffからRuntimeの同期deep-copy完了までexact bytesを有効に保ち、callback stackで寿命が終わるobjectを指しません。Runtimeはcallback return後、他のcallback/Port call/public returnより先にlengthを検証してexact bytesをdeep-copyし、元pointerを永続化しません。DEFER/FATAL/非KNOWN_RESULTではcopyしません。
- Runtimeはcallback前にactive token slot、result/Disposition record、invalid-token tombstone、reconcile stateのlocal capacityをreserveします。不足時はcallbackを呼ばず`APPLICATION_BUSY`またはcapacity Dispositionへ収束させます。
- Runtimeはnon-zero clock epochを持つtrusted local sampleからtoken expiryを作れる場合だけcallbackを呼びます。**trusted sample の `now_ms=0` は legal** です。clock uncertain/port failure/checked addition overflowではtokenを発行せずretryable receiver-unavailable pathへ進みます。
- DesiredState receiverはcallback前にlocal clockをsampleします。M1aではsampleのclock epoch IDが`deadline_clock_epoch_id`とexactly一致し、`now_ms < absolute_effect_deadline_ms`の場合だけapplicationへ新規dispatchします。epoch不一致またはdeadline到達後はcallbackを呼ばず`STALE_NOT_APPLIED` Dispositionをdurably commitし、APPLIED/VERIFIED成功を生成しません。M1a Simulatorは全Runtimeでshared virtual clock epochを使用します。
- Callbackはowner thread上、`runtime_step`内だけで呼ばれます。
- Callback中、query API以外のNinlil APIを呼んではなりません。
- M1a delivery tokenは`context_id = delivery.transaction_id`、`generation = N`（当該Deliveryのdurable counter。1始まりのchecked `uint64_t`）、callback前clock sampleのepoch ID、`expires_at_ms = completion_expires_at_ms`です。tokenはそのRuntime内のtransaction/delivery/digest/expiryへbindingし、別Runtime/transactionへ移植できません。`N+1`がchecked不能ならcallbackを呼ばず`COUNTER_EXHAUSTED`でfail closed/reconcileします。
- Durable counterは常に`delivery_count = callback_invocations = token_generation = N`です。`N`はactual `on_delivery`開始回数であり、**DELIVERY_START FULL commitだけ**が3値を同一post値へchecked +1します。REDELIVER / reconcile actionは`N`を増やしません。`delivery_view.delivery_count == token.generation == N`です。Reconcile viewの`prior_callback_invocations`は当該Deliveryで既に開始commitしたcallback回数（=`N`）のchecked uint64で、REDELIVER直後（次START前）も同じ`N`を写します。どちらもnarrowingしません。
- Runtimeはcallbackを呼ぶ**前**に上記tokenを割り当て、`delivery_started_at_ms`（sample `now_ms` の写し。**0 可**）と`completion_expires_at_ms = checked(delivery_started_at_ms + application_completion_timeout_ms)`（descriptor 上 timeout≥1 のため **expiry は non-zero**；overflow なら token 発行 0）を計算し、physical `DELIVERY_STARTED`、`token_state=ACTIVE`、transaction/delivery/digest binding、post `N`を1つの`FULL` transactionへcommitします。ACTIVE の RESULT_CACHE timer 5-tuple は17章どおり: epochs non-zero かつ一致、`delivery_started_at_ms` 任意 u64、`token_expires_at_ms = completion_expires_at_ms` かつ both non-zero。commit失敗または不明ならcallbackを呼びません。
- `CALLBACK_COMPLETE`では`out_sync_result`がvalid必須です。Runtimeがcallback return後にresult cache/Dispositionとtoken invalidation（`token_state=CONSUMED`、timer 5-tuple **retain**。`delivery_started_at_ms=0` の retain 可）を同じ`FULL` transactionへcommitします。commit前にReceiptを発行しません。
- callback return後のtrusted clock sampleが`completion_expires_at_ms`を超えていれば、同期resultもcommitせずtimeout/recovery規則を適用します。同時刻なら同期resultを先にreduceします。
- `CALLBACK_DEFER`ではresultを無視します。**追加FULL writeなし**。physical RESULT_CACHEは`delivery_state=DELIVERY_STARTED` + ACTIVEのままです。DEFERRED_WAITは同一Runtime instanceのin-memory/public projectionだけです。Applicationはcallback中にdelivery tokenの値をcopyし、`ninlil_delivery_complete()`成功またはcompletion timeoutまでだけ使用できます。token pointer自体を保持してはなりません。budget上の未使用第2 state-transition reservationは既存規則どおり同一stepへ返します。
- Deferred中、payload pointerは無効になります。Applicationは必要なdataを自分でcopyします。
- `CALLBACK_FATAL`、unknown callback action、`CALLBACK_COMPLETE`だがinvalid resultでは、callback前にcommit済みtokenを放置しません。Runtimeはtoken invalidation（`token_state=RECOVERY_REQUIRED_TOMBSTONE`、timer 5-tuple **retain**、started_at の zero 可）、active slot release、Delivery=`RECOVERY_REQUIRED`、effect certainty=`EFFECT_POSSIBLE`を1つのFULL transactionへcommitし、positive Receiptを生成しません。reasonはFATALで`APPLICATION_FAILED`、unknown/invalidで`CALLBACK_CONTRACT`、Runtime healthは`DEGRADED`です。Controller receiverでは`controller.before_callback_recovery_commit` / `controller.after_callback_recovery_commit`、Endpoint receiverでは`endpoint.before_callback_recovery_commit` / `endpoint.after_callback_recovery_commit`のexact pairを通ります。
- 上記recovery commit後は同じRuntime instanceで同Deliveryへ`on_delivery`を再度呼びません。restart/recoveryでapply contractに従い`on_reconcile`またはsafe idempotent recoveryを行います。commit failure/unknownでもReceiptを出さずdeliveryをfenceしてDEGRADEDにします。
- `on_reconcile`の`REDELIVER`は`N`を増やさずINBOXへ戻し（past token tombstone保持、result tupleはZERO）、**次のDELIVERY_START**が`N`を+1して新ACTIVE tokenで再callbackします。`KNOWN_RESULT`はresult commit、`RETRY_LATER`はdescriptorのfixed `retry_backoff_ms`だけを使うlocal待機、`OUTCOME_UNKNOWN`はremoteへunknown Dispositionを返します（token CONSUMED tombstone一意形）。`RETRY_LATER`では`out_known_result`全体をignoreするため、Application指定delayは存在しません。Runtimeはtrusted local sampleから`retry_not_before_ms = checked(now_ms + descriptor.retry_backoff_ms)`を作り、clock uncertain/epoch不一致/overflowではtimerを推測せずfail closedします。Public/remote absolute retry timeを生成しません。per-delivery `reconcile_invocation_count`はactual `on_reconcile` entry回数で、entry直前claimがchecked +1し、同generationのcrash再実行でも別claimとして`I`を増やし`I>G`を許します。same-record不変は`G≥1,I≥0,G≤I+1`であり`G=I+1`必須ではありません（17/13章）。
- Unknown reconcile actionまたはinvalid `KNOWN_RESULT`はphysical `RECOVERY_REQUIRED`を維持し、RESULT の E_REC reason を **`CALLBACK_CONTRACT` へ置換**（token tombstone identity/timers/`N`は維持）して health prio3 source（RECOVERY_REQUIRED + exact CALLBACK_CONTRACT）を成立させます。positive Disposition/Receipt は commit しません。同じ recovery pass で再 callback しません。valid terminal reconcile で source clear します。

Application result validation:

- `APP_RESULT_POSITIVE_EVIDENCE`は`evidence_stage`がserviceのsupported non-zero stage、`disposition == NONE`、`reason == NONE`、effect certainty `NONE`、retry guidance `NEVER`、`retry_delay_ms == 0`、evidenceが0〜128 bytesです。
- `APP_RESULT_DISPOSITION`は`evidence_stage == NONE`、dispositionがM1aのknown non-zero値、evidenceがemptyで、次のexact combinationだけを受理します。同じ表をBearer `DISPOSITION` validationにも使用します。

| Disposition | Effect certainty | Retry guidance | Reason | retry_delay_ms |
| --- | --- | --- | --- | ---: |
| `RETRY_LATER` | `NO_EFFECT_PROVEN` | `RETRY_SAME_AFTER` | `RECONCILE_RETRY_LATER` | 0〜max |
| `INVALID_PAYLOAD` | `NO_EFFECT_PROVEN` | `RETRY_MODIFIED` | `APPLICATION_FAILED` | 0 |
| `UNSUPPORTED_SCHEMA` | `NO_EFFECT_PROVEN` | `RETRY_MODIFIED` | `APPLICATION_FAILED` | 0 |
| `UNAUTHORIZED_SERVICE` | `NO_EFFECT_PROVEN` | `RETRY_MODIFIED` | `TARGET_UNAUTHORIZED` | 0 |
| `STALE_NOT_APPLIED` | `NO_EFFECT_PROVEN` | `RETRY_NEVER` | `APPLICATION_FAILED` | 0 |
| `APPLICATION_BUSY` | `NO_EFFECT_PROVEN` | `RETRY_SAME_AFTER` | `RECEIVER_UNAVAILABLE` | 0〜max |
| `APPLY_FAILED` | `NO_EFFECT_PROVEN` | `RETRY_SAME_AFTER` | `APPLICATION_FAILED` | 0〜max |
| `APPLY_FAILED` | `EFFECT_POSSIBLE` | `RETRY_OPERATOR_ACTION` | `APPLICATION_FAILED` | 0 |
| `VERIFY_FAILED` | `EFFECT_POSSIBLE` | `RETRY_OPERATOR_ACTION` | `APPLICATION_FAILED` | 0 |
| `CAPACITY_EXHAUSTED` | `NO_EFFECT_PROVEN` | `RETRY_SAME_AFTER` | `CAPACITY_EXHAUSTED` | 0〜max |
| `OUTCOME_UNKNOWN` | `EFFECT_POSSIBLE` | `RETRY_OPERATOR_ACTION` | `OUTCOME_UNKNOWN` | 0 |

表の`max`は`NINLIL_M1A_MAX_RETRY_DELAY_MS`です。`NO_EFFECT_PROVEN`はapplicationがeffect未発生をdurably判断できる場合だけ使用し、不明なら`EFFECT_POSSIBLE`へ倒します。
- Runtimeはresult cache/Receiptをtransaction ID、attempt ID、content digest、EventFact event IDまたはDesiredState generation、evidence stage/disposition、exact evidence bytesへbindします。M1a Application resultにapplication申告の独立hash fieldはなく、その存在を推測しません。
- Disposition固有の意味は`ninlil_disposition_t`、effect可能性は`ninlil_effect_certainty_t`が正本です。reason/guidanceは上表から逸脱できません。
- `retry_delay_ms`はrelative durationで0〜`NINLIL_M1A_MAX_RETRY_DELAY_MS`です。0は追加指定なし、non-zeroを許すのは上表で`0〜max`のrowだけです。
- retryable Dispositionの内部`retry_not_before = checked(now_ms + max(retry_backoff_ms, retry_delay_ms))`です。受信側Runtime自身のlocal clockで計算し、checked addition不能は`COUNTER_EXHAUSTED`として新attemptを作りません。M1aはpublic absolute retry time、exponential backoff、jitterを使いません。
- Synchronous callbackのCOMPLETE/KNOWN_RESULTが上記に違反した場合は`CALLBACK_CONTRACT`です。positive Receiptを生成せず、deliveryをrecovery/reconcile対象としてFULL commitします。Public `ninlil_delivery_complete()` inputの違反は下のordered tableどおり`NINLIL_E_INVALID_ARGUMENT`で、matching active tokenをinvalid化しません。

Deferred completion timeout:

- completion expiryはcallback return時ではなく、callback前にcommitした`checked(delivery_started_at_ms + application_completion_timeout_ms)`です（`delivery_started_at_ms=0` 可、timeout≥1 により expiry non-zero）。callback実行時間もbounded windowへ含めます。
- callbackが`DEFER`を返した場合、**追加FULL writeなし**。callback前にcommit済みのphysical `DELIVERY_STARTED` + ACTIVE tokenを保持し、active `DEFERRED_WAIT`は同一Runtime instanceのin-memory/public projectionだけです（Domain Storeへ`delivery_state=3`を書いてはなりません）。
- callback中にprocessがcrashした場合もdurable `DELIVERY_STARTED` + ACTIVEが残ります。recovery（create/kind21 または destroy kind19）は旧processでcopyされたtokenをcompletion可能とせず、**EXPIRED** + E_REC **`OUTCOME_UNKNOWN`** + `RECOVERY_REQUIRED`へFULL commitし、apply contractに従い`on_reconcile`へ進めます（timeout reason と混同しない）。
- timeout到達時、Runtimeはoperation kind **10 phase 2 TOKEN_TIMEOUT** として`token_state=EXPIRED` tombstone（timer 5-tuple retain）、E_REC **`APPLICATION_COMPLETION_TIMEOUT`**、active slot解放、`RECOVERY_REQUIRED`をFULL commitします（role `*_token_timeout_commit`）。

`ninlil_delivery_complete()` validation/status precedenceは次のordered tableが正本です。Earlier rowで終了したcallはlater rowのclock、evidence copy、storage mutationを行いません。

| Order / condition | Exact public status | Token / delivery effect |
| --- | --- | --- |
| 1. runtime/token/result NULL、token/resultのABI header・required size不正 | NULLは`NINLIL_E_INVALID_ARGUMENT`、header/sizeは`NINLIL_E_ABI_MISMATCH` | lookup 0、変更0 |
| 2. wrong owner execution context / callback内re-entry | `NINLIL_E_WRONG_THREAD` / `NINLIL_E_REENTRANT` | lookup 0、変更0 |
| 3. token context/clock epoch all-zero、generation 0、result reserved/enum/view/length不正、7.2 exact result tuple不一致、evidence 128 bytes超 | `NINLIL_E_INVALID_ARGUMENT` | lookup/clock/copy 0。Matching active tokenがあってもactiveのまま |
| 4a. context IDがcurrent Runtime namespaceのactive/retained token indexに存在しない | `NINLIL_E_NOT_FOUND` | 変更0。別Runtime/random contextを含む |
| 4b. context IDはknownだがactive tokenなし、retained CONSUMED/EXPIRED/RECOVERY_REQUIRED_TOMBSTONE tombstone（result-cache retention中）、またはactive contextに対してgeneration/clock epoch/expires-at/bindingが不一致 | `NINLIL_E_INVALID_STATE` | authoritative recordを変更せず、実際のactive tokenが別にあればactiveのまま。cleanup後のrecord不在は4a `NOT_FOUND` |
| 5a. clock Port temporary failure、valid sampleだが`CLOCK_UNCERTAIN`、またはtrusted sampleのepochがtoken epochと不一致 | `NINLIL_E_CLOCK_UNCERTAIN` | result/copy/commit 0、token markerはこのcallではactiveのまま。epoch mismatchはrecovery workをqueueし、old tokenをsuccessへ戻さない |
| 5b. clock Port permanent failure、invalid/partial sample、same epoch内time regression | `NINLIL_E_DEGRADED` | health DEGRADED、result/copy/commit 0、token completionをrecoveryまでfence |
| 5c. trusted same epochで`now_ms > expires_at_ms`、timeout commit未完了 | timeout commit結果に従う。OKなら`NINLIL_E_INVALID_STATE` | application result/evidenceを読取り済みvalidation以上には使用せず、role固有token-timeout hook pairでtoken invalidation + slot release + `RECOVERY_REQUIRED`をFULL commit。exact expiry `==`はこのrowでなくcompletionが先 |
| 6. exact active token、trusted same epoch、`now_ms <= expires_at_ms`だがevidence deep-copy allocation failure | `NINLIL_E_CAPACITY_EXHAUSTED` | storage write 0、token active、callerはexpiry前にretry可 |
| 7. result cache + token invalidation + slot release FULL commit OK | `NINLIL_OK` | role固有result-cache hook pairを通り、tokenはconsumed、result/evidenceはdurable、active slot解放。Receiptはcommit後だけ |

Order 5c/7のStorage status mappingとretry fenceは次で固定します。

| Storage observation before/at FULL commit | Public status | Token rule |
| --- | --- | --- |
| `BUSY` | `NINLIL_E_WOULD_BLOCK` | authoritative active marker不変。5cではresult成功へ戻れず、timeout commitだけretry |
| `NO_SPACE` | `NINLIL_E_CAPACITY_EXHAUSTED` | authoritative active marker不変。Reserved capacity違反をdiagnosticへ記録 |
| definite `IO_ERROR` / definite non-commit failure | `NINLIL_E_STORAGE` | authoritative active marker不変。Completion pathはexpiry前だけretry可、5cはtimeout commitだけretry |
| `CORRUPT` / `UNSUPPORTED_SCHEMA` / impossible internal `BUFFER_TOO_SMALL` | `NINLIL_E_STORAGE_CORRUPT` | health DEGRADED、token/deliveryをrecoveryまでfenceし、caller retry禁止 |
| `COMMIT_UNKNOWN` | `NINLIL_E_STORAGE_COMMIT_UNKNOWN` | health DEGRADED、tokenをrecoveryまでfence。Callerは同tokenを再callせず、同じRuntime instanceのstorage reopen後authoritative recordがactiveなら残時間内completion可、consumed/expiredなら`INVALID_STATE`。Process restartでは旧tokenをactiveへ戻さない |

Storage `NOT_FOUND`はorder 4aのindex/recordとも不存在ならAPI NOT_FOUNDです。Known active indexがmarker不存在を指す場合はstorage corruptionで、random contextをcorruptionへ格上げしません。

Complete成功/timeout成功でactive deferred slotを直ちに解放します。Invalid token tombstone（CONSUMED/EXPIRED/RECOVERY_REQUIRED_TOMBSTONE、timer 5-tuple retain。`delivery_started_at_ms=0` 可）はserviceの`required_dedup_window_ms`以上かつruntime `result_cache_retention_ms`以内のbounded result-cache retentionでRESULT_CACHE上に保持します。保持中のlate/double/stale completion（known context）は`NINLIL_E_INVALID_STATE`、retention cleanup後のrecord不在は`NINLIL_E_NOT_FOUND`です。Epoch changeまたはRuntime restartで旧tokenをactiveへ復元しません。
- `APPLY_IDEMPOTENT`は同じabsolute effectを再dispatchできます。
- `APPLY_APPLICATION_DEDUP`は次の`runtime_step`で`on_reconcile`を呼びます。
- active deferred tokenは`max_deferred_tokens`と`max_nonterminal_deliveries`を同時に1消費します。complete/timeoutでdeferred token slotだけを解放し、reconcile完了まではdelivery reservationを解放しません。expired tokenのためactive slotを永久消費しません。

Application/Ninlil atomicity:

- M1aではapplication DBとNinlil storageを同一transactionにしません。
- Application effect/store成功後、Ninlil result cache commit前にcrashし得ます。
- `IDEMPOTENT`は同じabsolute effectの再実行を安全にします。
- `APPLICATION_DEDUP`はtransaction ID/Event IDをapplication storeへ永続化し、reconcileで既知resultを返します。
- Runtimeだけを見てexactly-once physical effectを主張してはいけません。

## 8. Submission ABI

```c
typedef struct ninlil_submission {
    NINLIL_STRUCT_HEADER;
    uint16_t schema_major;
    uint16_t schema_minor;
    uint32_t reserved_zero;
    const ninlil_concrete_target_t *targets;
    uint32_t target_count;
    ninlil_evidence_stage_t required_evidence;
    uint64_t effect_deadline_ms;
    uint64_t evidence_grace_ms;
    ninlil_bytes_view_t idempotency_key;
    ninlil_digest256_t content_digest;
    ninlil_id128_t event_id;
    uint64_t generation;
    ninlil_bytes_view_t payload;
} ninlil_submission_t;

#define NINLIL_ASSURANCE_NONE               ((ninlil_assurance_profile_t)0u)
#define NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL ((ninlil_assurance_profile_t)1u)

typedef struct ninlil_admission_assurance {
    NINLIL_STRUCT_HEADER;
    ninlil_assurance_profile_t assurance_profile;
    uint32_t submission_validated;
    uint32_t target_roster_fixed;
    uint32_t descriptor_snapshot_fixed;
    uint32_t local_journal_committed;
    uint32_t local_capacity_reserved;
    uint32_t idempotency_mapping_committed;
    uint32_t origin_grant_snapshot_committed;
    uint32_t remote_capacity_reserved;
    uint32_t route_feasibility_verified;
    uint32_t receive_window_reserved;
    uint32_t bearer_capacity_reserved;
    uint32_t airtime_reserved;
    uint32_t compliance_permit_issued;
    uint32_t reserved_zero;
} ninlil_admission_assurance_t;

typedef struct ninlil_submission_result {
    NINLIL_STRUCT_HEADER;
    ninlil_submission_kind_t kind;
    ninlil_reason_t reason;
    ninlil_retry_guidance_t retry_guidance;
    uint32_t reserved_zero;
    uint64_t retry_delay_ms;
    ninlil_id128_t transaction_id;
    ninlil_digest256_t canonical_submission_digest;
    ninlil_admission_assurance_t assurance;
} ninlil_submission_result_t;
```

Rules:

- `target_count == 0`なら`targets == NULL`、`target_count > 0`なら`targets != NULL`です。M1a admitted countはexactly 1、descriptor/runtime target limitも1です。count 0または2以上はpointer invocation errorではなく`TARGET_COUNT_UNSUPPORTED` rejectionです。
- M1aにselector fieldはありません。
- Runtimeはadmission commit前にtargets/payload/keyをdeep copyします。
- idempotency keyは1〜64 bytesです。
- `schema_major`はdescriptor exact match、`schema_minor`はdescriptor min/max内です。違反は`NINLIL_OK + REJECTED + INVALID_SCHEMA`です。
- payload lengthはdescriptor/runtime上限内、required evidenceはdescriptor maskでsupportedです。違反はそれぞれ`INVALID_PAYLOAD_LENGTH`、`EVIDENCE_UNSUPPORTED` rejectionです。
- Idempotency scopeは`source application instance + namespace + service ID`です。descriptor revisionはscopeではなくcanonical submission digestに含めます。
- 全familyのcaller-key mappingは`idempotency key length + exact raw bytes -> transaction ID + canonical submission digest`をdurable正本とします。SHA-256等のkey hashは補助indexとしてだけ使用でき、hash一致後もlength + 全raw bytesを比較します。Hash-only同一性、collision時のalias、raw keyを保存しない実装は禁止です。
- DesiredStateCommandは同じscope/key/canonical digestで`ALREADY_ADMITTED`、同じscope/keyで異なるdigestは`IDEMPOTENCY_CONFLICT`です。
- EventFactは同じscope内に、durable `event_id -> transaction_id + canonical_submission_digest + exact idempotency key length/bytes` mappingを持ちます。同じevent ID、同じcanonical digest、同じidempotency keyの3条件が揃う場合だけ既存transactionの`ALREADY_ADMITTED`です。
- EventFactはtripleの1要素でも異なり、既存key mappingまたはevent mappingと交差すれば`IDEMPOTENCY_CONFLICT`です。same event ID/digestでkeyだけが違う場合、same key/business contentでevent IDを変えたためcanonical digestが違う場合、key mappingとevent mappingが別transactionを指す場合をすべて含みます。alias mappingを追加せず既存mappingを上書きしません。Event retryはevent IDとidempotency keyの両方を不変にします。
- EventFact conflict結果へ返すexisting transaction ID / canonical digestは決定的に選びます。Caller-key mappingが存在する場合は常にそのpersist済みpairを返し、caller-key mappingがなくevent ID mappingだけが存在する場合に限りevent mappingのpairを返します。両mappingが別transactionを指す破損・競合状態でもcaller-key mappingを優先し、2つのpairを混合しません。これはcallerが指定したidempotency keyをprimary public lookup boundaryに保ち、再提出ごとの結果を安定させる規則です。どちらかのmappingが参照するrecord自体を検証・読取りできない場合はconflictを合成せず、Storage corruption/errorとしてfail closedします。
- 新規EventFact admissionはkey mapping、event mapping、transaction、payload/spool、grant snapshotを同じFULL transactionでcommitします。event mapping capacityもadmission前にreserveし、required Receipt/explicit discard前は削除せず、terminal後も少なくとも`required_dedup_window_ms`保持します。
- DesiredStateはevent ID zero、generation non-zero、finite deadlineです。
- EventFactはevent ID non-zero、generation zero、`effect_deadline_ms == NINLIL_NO_DEADLINE`、`evidence_grace_ms == 0`です。
- Runtimeは新規admissionのresource reservation/storage transaction開始前にtrusted clockを1回sampleし、これを`admission reference sample`とします。`admitted_at_ms`と`admission_clock_epoch_id`はこの**pre-commit sample**の値であり、commit acknowledgement後に観測した時刻ではありません。sample、absolute timer、Submission/descriptor/source/target bindingをadmissionの同じFULL transactionへpersistします。
- DesiredStateの`effect_deadline_ms`はadmission referenceからのrelative duration、`evidence_grace_ms`もdurationです。Runtimeはsampleとのchecked additionでabsolute effect/evidence-close時刻をcommit前に作ります。caller absolute timestampではありません。`deadline_clock_epoch_id`はadmission sample epochで、absolute deadlineと常に対でstorage/Bearer/queryへ運びます。EventFactのdeadline epochはall-zeroです。
- Ninlilのownership、assurance、`transaction_sequence`、ADMITTED resultはFULL admission commitがOKになった時点でだけ成立します。pre-commit sample取得やstaged writeだけでは所有しません。definite failureはcaller ownership、commit unknownは`NINLIL_E_STORAGE_COMMIT_UNKNOWN`です。
- Admission commit後、RuntimeはCommandをdispatchする前にcurrent trusted timeを再評価します。同じdeadline epochで`now_ms >= absolute_effect_deadline_ms`なら、admitted transactionを`EXPIRED / DEADLINE_ELAPSED_BEFORE_DISPATCH`へterminalizeし、新attemptを作りません。このpost-admission terminalizationのFULL commitは`controller.before_deadline_terminal_commit` / `controller.after_deadline_terminal_commit`を通ります。commit直後crashでもrecoveryが同じguardとhook pairを最初に実行します。
- 上記post-commit expiryはadmission rejectionへ巻き戻しません。`ninlil_submit()`は`NINLIL_OK`、admitted kind、persist済みtransaction ID/assuranceを返し、query時点では既にterminalでも構いません。post-commit clockがuncertain/epoch不一致ならownershipを維持し、dispatchせずclock recoveryを待ちます。
- RuntimeはSHA-256(payload)を計算し、content digest不一致をAPI invalid argumentとして拒否します。
- Struct、pointer、length、digest byte不一致はAPI invocation errorです。一方、family/descriptorが許さないdeadlineは構文上有効なSubmissionです。EventFactのfinite deadlineまたはnon-zero graceは`NINLIL_OK + REJECTED + EVENTFACT_DEADLINE_UNSUPPORTED`、DesiredStateの`NINLIL_NO_DEADLINE`または範囲外deadline/graceは`NINLIL_OK + REJECTED + DEADLINE_INVALID`です。
- Submission resultの全field matrixは次で固定します。Zero digestはalgorithm/reserved/32 bytesがall-zero、zero assuranceはprofile/全flag/reservedがzeroです。

| API status / kind | reason / guidance / delay | transaction ID | canonical submission digest | nested assurance |
| --- | --- | --- | --- | --- |
| API error / `SUBMISSION_INVALID` | `NONE / RETRY_NEVER / 0` | zero | zero | nested headerを含めall-zero |
| `NINLIL_OK / SUBMISSION_REJECTED` | exact non-zero rejection reason / 4.4 default-or-provider-valid guidance / guidance規則のrelative delay | zero | zero（canonical計算へ到達済みでも公開しない） | current ABI header/size、`ASSURANCE_NONE`、全flag zero |
| `NINLIL_OK / SUBMISSION_IDEMPOTENCY_CONFLICT` | `IDEMPOTENCY_CONFLICT / RETRY_MODIFIED / 0` | conflictしたexisting non-zero transaction ID | existing transactionのpersist済みnon-zero canonical digest | current ABI header/size、`ASSURANCE_NONE`、全flag zero |
| `NINLIL_OK / SUBMISSION_ADMITTED_READY` | `NONE / RETRY_NEVER / 0` | new admitted non-zero transaction ID | admissionへFULL commitしたnon-zero canonical digest | current ABI header/size、persist済み`FOUNDATION_M1A_LOCAL` snapshot |
| `NINLIL_OK / SUBMISSION_ALREADY_ADMITTED` | `NONE / RETRY_NEVER / 0` | existing non-zero transaction ID | existing persist済みnon-zero canonical digest | current ABI header/size、existing persist済み`FOUNDATION_M1A_LOCAL` snapshot |

`SUBMISSION_INVALID`はAPI errorだけで生成し、`NINLIL_OK`と組み合わせません。Libraryはsemantic `NINLIL_OK` resultでnested assurance headerを初期化し、API errorではouter result header以外をzeroにします。Rejected/conflictにpartial assuranceを返しません。

- `ADMITTED_READY`と`ALREADY_ADMITTED`は`FOUNDATION_M1A_LOCAL` assuranceを返します。前者はadmissionと同じFULL commitで固定し、後者はpersist済みsnapshotを返します。
- 両admitted kindでは`submission_validated`、`target_roster_fixed`、`descriptor_snapshot_fixed`、`local_journal_committed`、`local_capacity_reserved`、`idempotency_mapping_committed`が1です。EventFactの`idempotency_mapping_committed`はkey mappingとevent ID mappingの両方が同じtransactionへcommit済みであることを含みます。`origin_grant_snapshot_committed`はEventFactだけ1、DesiredStateは0です。
- `remote_capacity_reserved`、`route_feasibility_verified`、`receive_window_reserved`、`bearer_capacity_reserved`、`airtime_reserved`、`compliance_permit_issued`はM1aで常に0です。false fieldを省略したり暗黙の保証へ格上げしません。
- Submission resultの`retry_delay_ms`はrelative durationで、REJECTEDかつ`RETRY_SAME_AFTER`だけ0〜`NINLIL_M1A_MAX_RETRY_DELAY_MS`を返せます。0はdescriptor fixed backoffだけを使う意味です。admitted/already/conflict、`RETRY_NEVER`、`RETRY_MODIFIED`、`RETRY_OPERATOR_ACTION`では0です。

## 9. Transaction、query、list、cancel

```c
typedef struct ninlil_target_snapshot {
    NINLIL_STRUCT_HEADER;
    ninlil_concrete_target_t target;
    ninlil_transaction_state_t state;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    ninlil_evidence_stage_t latest_evidence;
    uint32_t attempt_in_cycle;
    uint64_t retry_cycle_id;
    uint64_t cumulative_attempts;
} ninlil_target_snapshot_t;

typedef struct ninlil_transaction_snapshot {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t transaction_id;
    ninlil_id128_t event_id;
    ninlil_party_t source;
    ninlil_service_identity_t service;
    ninlil_digest256_t content_digest;
    ninlil_family_t family;
    ninlil_transaction_state_t state;
    ninlil_outcome_t outcome;
    ninlil_deadline_verdict_t deadline_verdict;
    ninlil_evidence_stage_t required_evidence;
    ninlil_evidence_stage_t latest_evidence;
    ninlil_reason_t reason;
    ninlil_event_park_cause_t event_park_cause;
    uint64_t generation;
    ninlil_id128_t admission_clock_epoch_id;
    uint64_t admitted_at_ms;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    uint64_t transaction_sequence;
    uint64_t record_revision;
    uint64_t event_spool_revision;
    uint32_t target_count;
    uint32_t target_capacity;
    ninlil_target_snapshot_t *targets;
    uint32_t has_late_evidence;
    uint32_t explicitly_discarded;
    ninlil_admission_assurance_t assurance;
} ninlil_transaction_snapshot_t;

typedef struct ninlil_transaction_summary {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t transaction_id;
    ninlil_service_identity_t service;
    ninlil_family_t family;
    ninlil_transaction_state_t state;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    ninlil_id128_t admission_clock_epoch_id;
    uint64_t admitted_at_ms;
    uint64_t transaction_sequence;
    uint64_t record_revision;
} ninlil_transaction_summary_t;

typedef struct ninlil_query {
    NINLIL_STRUCT_HEADER;
    uint64_t after_transaction_sequence;
    ninlil_id128_t admission_clock_epoch_id;
    uint64_t admitted_at_or_after_ms;
    uint32_t family_mask;
    uint32_t include_terminal;
    uint32_t include_nonterminal;
    uint32_t has_admitted_at_filter;
    uint32_t reserved_zero;
} ninlil_query_t;

typedef struct ninlil_transaction_page {
    NINLIL_STRUCT_HEADER;
    ninlil_transaction_summary_t *items;
    uint32_t item_capacity;
    uint32_t item_count;
    uint64_t next_after_transaction_sequence;
    uint32_t has_more;
    uint32_t reserved_zero;
} ninlil_transaction_page_t;

#define NINLIL_CANCEL_FENCED_BEFORE_DISPATCH ((ninlil_cancel_kind_t)1u)
#define NINLIL_CANCEL_PENDING_REMOTE_FENCE  ((ninlil_cancel_kind_t)2u)
#define NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE ((ninlil_cancel_kind_t)3u)
#define NINLIL_CANCEL_ALREADY_TERMINAL      ((ninlil_cancel_kind_t)4u)

typedef struct ninlil_cancel_result {
    NINLIL_STRUCT_HEADER;
    ninlil_cancel_kind_t kind;
    ninlil_reason_t reason;
    ninlil_outcome_t current_outcome;
    uint32_t reserved_zero;
} ninlil_cancel_result_t;
```

Public snapshot projectionはsingle targetのためtop-levelとtargetを次のclosed ruleで作ります。

- `target_count == 1`、`targets[0].target`はadmission concrete target exact copyです。Top-levelとtargetの`state`、`outcome`、`reason`、`latest_evidence`は常にvalue exact一致します。Aggregate用の別reason/stateを作りません。
- Internal READY/HELD_READY→`TXN_READY`、ATTEMPT_PREPARED→`TXN_DISPATCHING`、AWAITING_RECEIPT/AWAITING_EVIDENCE/AWAITING_GRACE→`TXN_AWAITING_EVIDENCE`、RETRY_WAIT/RECONCILE_WAIT→`TXN_WAITING_WINDOW`、Event PARKED_RETRY→`TXN_PARKED_RETRY`、全terminal→`TXN_TERMINAL`です。CommandでPARKED_RETRYを生成しません。
- Non-terminal Outcomeは常に`NONE`です。Terminal stateだけが5つのreachable non-zero Outcomeを持ち、`SUPERSEDED_RESERVED`は0件です。
- Public `TXN_READY` / `TXN_DISPATCHING`と通常のaccepted-send AWAITINGへ入るcommitはreasonを`NONE`へresetします。WAITING_WINDOWはその待機を作ったexact durable reason、cancel pending/too-late AWAITINGは対応cancel reason、deadline後のevidence waitは`EFFECT_POSSIBLE_EVIDENCE_PENDING`、PARKEDは常に`EVENT_RETRY_CYCLE_PARKED`、terminalはOutcomeを決めたpersist済みterminal reasonです。Late evidenceはterminal reasonを変えません。
- `latest_evidence`はsummaryのlatest stage、未受信は`NONE`です。Top/targetで同じ値を返します。

Family-specific all-field rule:

| Field | DesiredStateCommand | EventFact |
| --- | --- | --- |
| `event_id` / `generation` | zero / admitted non-zero generation | admitted non-zero event ID / 0 |
| deadline epoch/time/grace | non-zero admitted epoch / finite absolute time / admitted grace | all-zero epoch / `NINLIL_NO_DEADLINE` / 0 |
| `deadline_verdict` | active before deadline=`PENDING`; proven in-time=`MET`; proven late/EXPIRED=`MISSED`; time/effect unresolved after deadline or OUTCOME_UNKNOWN=`INDETERMINATE`; CANCELLED/FAILED before deadline proof=`PENDING` | always `NOT_APPLICABLE` |
| `event_park_cause` | always `NONE` | PARKEDだけexact non-zero cause、他stateは`NONE` |
| target `attempt_in_cycle` / `retry_cycle_id` | 0 / 0 | current cycle attempts 0..8 / admissionで1、resumeごとchecked +1 |
| target `cumulative_attempts` | Command lifetimeのcommitted attempts used | Event lifetimeの全committed attempts合計 |
| `event_spool_revision` | 0 | admission=1からchecked mutation value、terminal retention中もnon-zero |
| `has_late_evidence` | summary late flag 0/1 | summary late flag 0/1 |
| `explicitly_discarded` | 0 | audited discard terminalだけ1、required Receipt terminal/activeは0 |

Top-level immutable transaction/source/service/content/family/admission time/sequenceはadmission record exact copy、assuranceもpersist済みsnapshot exact copyです。`record_revision`だけはrecord mutationでsaturating増加します。Unused ID/numeric/enum/nested bytesを実装固有値で埋めず上表のzero/constantにします。

M1a listは1 transactionを1件だけenumerateし、mutation change feedではありません。`transaction_sequence`は同じstorage namespaceでrestartを跨いでpersistし、admission FULL commitで1からmonotonic付与するimmutable値です。新値をchecked incrementできなければ新規admissionを`COUNTER_EXHAUSTED`で拒否し、既存transactionへ影響させません。

List orderは`transaction_sequence`昇順、`after_transaction_sequence`はexclusiveです。0は先頭を意味します。`next_after_transaction_sequence`はitemありなら最後に返したsequence、0件ならinput afterと同値です。`has_more`は同じstorage read snapshotにnext sequenceより後のmatching transactionが1件以上ある場合だけ1です。pagination中にtransaction stateが変わってもsequenceを変えず、同じtransactionを別sequenceで再列挙しません。per-mutation change feedは後続milestoneです。

`ninlil_transaction_page_t.item_capacity`は全matching件数を収めるrequired buffer sizeではなく、callerが選ぶ1 pageの最大件数です。Valid query/list callはmatching件数がcapacityを超えても`NINLIL_OK`で、先頭から`min(item_capacity, matching_count)`件、`item_count`、cursor、`has_more`を返します。通常paginationで`NINLIL_E_BUFFER_TOO_SMALL`を返しません。

- `item_capacity == 0`では`items == NULL` requiredです。Callはvalidで、`item_count = 0`、`next_after_transaction_sequence = query.after_transaction_sequence`、同じread snapshotにmatching rowが1件以上あれば`has_more = 1`、なければ0を返します。Callerは進行するにはnon-zero capacityで再callします。
- `item_capacity > 0`では`items != NULL`で、callerは全item_capacity要素のABI headerを初期化します。1要素でもheader不正なら`NINLIL_E_ABI_MISMATCH`、items全体を変更せず、page header/pointer/capacity以外をzeroにします。
- Successでは先頭`item_count`要素だけを書き、余剰要素を変更しません。Partial pageはerrorでなく、最後に書いたimmutable sequenceをnext cursorとし、同じread snapshotに後続matching rowがあれば`has_more = 1`、なければ0です。

`record_revision`はadmissionで1、transaction recordを変えるFULL commitごとにincrementするobservability値です。`UINT64_MAX`でsaturateし、CAS、pagination、state guardには使用しません。Callerはtarget/item配列の各要素へABI headerを初期化します。

Query booleanは0/1だけです。`include_terminal == include_nonterminal == 0`はinvalidです。`has_admitted_at_filter == 0`ではfilter epoch/timeはzero、1ではepoch ID non-zeroで、同じadmission epochかつ`admitted_at_ms >= admitted_at_or_after_ms`だけを含めます。異なるepochの数値を比較しません。

EventFact queryは`event_spool_revision`をnon-zeroで返し、management requestのexpected revisionはこの値を使用します。DesiredStateでは0です。`retry_cycle_id`と`cumulative_attempts`はchecked uint64、`attempt_in_cycle`は0〜`NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE`です。

`transaction_query`はadmission時にFULL commitしたassurance snapshotをrestart後も同値で返します。現在のroute/bearer状態から再計算したり、falseだったremote/airtime/compliance flagを後からtrueへ変更しません。

M1aの`transaction_query` / `transaction_list` domainは、**そのRuntimeがorigin admissionしたtransactionだけ**です。Controllerではlocal-origin DesiredStateCommand、Endpointではlocal-origin EventFactが対象です。Receiver側のinbound Command/Event `Endpoint Delivery`、result cache、cancel tombstone、Receipt/Dispositionだけのrecordはtransaction sequenceやadmission assuranceを持たず、listへ列挙しません。そのinbound transaction IDを同じRuntimeで`transaction_query`しても`NINLIL_E_NOT_FOUND`です。Receiver callback中にquery/listを呼べるというthread規則は、このdomainを拡張しません。Inbound delivery diagnostic APIは後続milestoneです。

Snapshot/summaryの`admission_clock_epoch_id`はFULL admission transactionへpersistしたpre-commit admission reference sampleのtrusted epochでnon-zero、`admitted_at_ms`をそのepochへbindします。Commandの`deadline_clock_epoch_id`は同じ値、EventFactのdeadline epochだけall-zeroです。

Snapshotの`source`、`service`、`content_digest`はadmission時のimmutable bindingで、top-level `family == service.family`です。idempotency keyとpayload byteはquery/listへ返しません。`service`のtext IDはinline `ninlil_text_id_t`なのでinternal pointerを公開せず、output structと一緒にcallerが所有します。List summaryも同じservice identityを返すため、namespace/serviceを確認してからtransaction IDで詳細queryできます。

`family_mask`は`NINLIL_FAMILY_MASK_EVENT_FACT`と`NINLIL_FAMILY_MASK_DESIRED_STATE`のORです。0は両familyを意味します。reserved bitが1なら`NINLIL_E_INVALID_ARGUMENT`です。

`ninlil_transaction_query()`はABI/null/buffer/thread validation後にexact transaction IDをcurrent Runtimeのstorage namespaceにあるorigin-admission domainでlookupします。Activeまたはretained terminal origin recordは`NINLIL_OK`です。Unknown ID、receiver-side inbound-only ID、またはterminal retention cleanup済みIDは`NINLIL_E_NOT_FOUND`で、13章のerror-output規則どおりheader/buffer pointer/capacity以外をzeroにし、placeholder snapshotやreasonを返しません。

### Targeted management linearization

`ninlil_cancel_request()`と、ledger missの`ninlil_event_resume()` / `ninlil_event_discard()`は、provider queueをdrainしない一方、対象ownerですでにdurableな過去input/timerを追い越しません。Outer/role/lookup/ledger-first validation後、new semantic operationを評価する直前に`clock.now`をexactly 1回取得します。

- `PORT_TEMPORARY_FAILURE`またはOK + `UNCERTAIN`は`NINLIL_E_CLOCK_UNCERTAIN`、permanent failure、partial/invalid/all-zero epoch、same-epoch regressionは`NINLIL_E_DEGRADED`です。Resultはcancel kind 0またはEvent kind INVALIDで他field zero、management/timer mutation 0、healthへ`CLOCK_UNCERTAIN` sourceをaddします。Clock callをretryしません。
- Trusted sampleをmanagement inputのlogical timeとします。対象ownerにすでにpersistする**correctness-closing** input/timerのうち、このsampleより古いものをlogical time昇順で先にreduceします。対象はvalid durable Receipt/Disposition/CancelResult/Delivery result、Command effect deadline/evidence close、current attempt Receipt timeout、delivery token timeout、reconcile resultです。`DISPATCH_DUE` / `RETRY_DUE`のような新しい外部effect機会、retention cleanup、別owner workはcatch-upしません。
- Exact same clock epoch/timeのgroupだけ13章priority→durable input sequence→target byte orderを使い、今回のmanagement inputも同groupへ入れます。したがってsame-time Receiptはcancel/discardより先、same-time cancel/discardはCommand deadlineより先、same-time Event attempt timeoutはresumeより先です。異なるtimeで後のmanagementが先のdeadline/timeoutを追い越しません。
- Catch-upは既存specific FULL commit/hookを使用し、failure/unknownならそのStorage statusで停止してmanagement resultを成功にしません。Bearer `receive_next/state/send`、TxGate、Origin provider、Entropy、application callbackを呼びません。Catch-upが新しいsend/callback candidateを作っても`runtime_step`へ残します。
- Persist済みcancel result、Event management ledger replay/conflictはcurrent stateを再評価しない既存ruleを優先し、clock call/catch-up 0です。Cleanup済みNOT_FOUNDとwrong-family errorもclock call 0です。

### DesiredState remote cancel

`ninlil_cancel_request`はController RuntimeがそのRuntimeからorigin admissionしたDesiredStateCommandへだけ使用できます。Validation precedenceとexact public resultは次です。

1. ABI/null/ID/header、owner thread、re-entryを先に検証します。失敗は対応API statusで、cancel resultはkind 0・他field zeroです。
2. Runtime roleが`CONTROLLER`でなければtransaction lookupをせず`NINLIL_E_UNSUPPORTED`です。Endpointが保持するinbound DesiredState transactionもpublic cancelのoriginにはなれません。
3. Controller namespaceにtransaction IDが存在しない、またはterminal retention cleanup済みなら`NINLIL_E_NOT_FOUND`です。kind/reason/outcomeはzeroで、tombstoneやnew recordを作りません。
4. Existing transactionがEventFactまたはlocal-origin DesiredStateCommandでなければ`NINLIL_E_UNSUPPORTED`です。EventFact diagnosticは`EVENT_FACT_IMMUTABLE`ですがAPI error resultへreasonを入れません。
5. Existing local-origin DesiredStateCommandでpersist済みcancel kindがあればclock call 0でそのkindを返します。Cancel recordがなくterminalなら`ALREADY_TERMINAL`です。Activeなら上記trusted clock/catch-up後のauthoritative stateだけをsemantic cancel reducerへ入力し、`NINLIL_OK`とnon-zero cancel kindを返します。Cleanup後は3のNOT_FOUNDです。

- ControllerのCommand admissionは自身のcancel attempt record/outbox metadata 1件だけをlocal resource計算へ含めます。Endpoint cancel tombstone/result capacityはinbound Command admission時にEndpointが自身のlocal resourceへ確保し、Controller assuranceはremote capacityを保証しません。1 transactionにつきremote cancelはexactly 1 logical allocation procedure、non-zero cancel attempt ID、prepared recordです。Candidate entropy drawは最大4 Port calls、valid IDを得たATTEMPT_PREPARE成功はtransaction lifetimeでexactly 1回で、restart、public API replay、send retryでもnew cancel ID/recordを作りません。
- Prepared cancel recordのdurable send gateは`NEVER_INVOKED`、`INVOKED_CLOSED`、`WOULD_BLOCK_RETRYABLE`の3-state closed registryだけを取ります。First sendはNEVER_INVOKED、retry sendはWOULD_BLOCK_RETRYABLEからだけ開始し、TxPermit取得後かつBearer call前に`INVOKED_CLOSED`をFULL commitします。このpre-send commitが失敗/unknown、またはcommit後send前にcrashした場合はconservatively closedのままで送信を推測・再実行しません。各send-gate state commitは`controller.before_cancel_send_gate_commit` / `controller.after_cancel_send_gate_commit`を通ります。
- Bearer `send(CANCEL_REQUEST)` invocationを同じprepared attempt ID、同じimmutable message bindingで再実行できるのは、直前のinvocationがdefinite no-acceptの`NINLIL_BEARER_WOULD_BLOCK`を返した場合だけです。各retryもfresh TxPermitを取得し、直前が再びWOULD_BLOCKなら同じruleを繰り返せます。直前のreturnがWOULD_BLOCK以外ならsend gateをdurably closedします。これには`NINLIL_BEARER_OK`（`ACCEPTED`/`DURABLE_CUSTODY`）、`LOST_UNKNOWN`、`UNAVAILABLE`、`DENIED`、`CORRUPT`、sendではinvalidな`EMPTY`/partial OK、およびそのCANCEL_REQUESTがEndpointへ届いた、またはcancel fenceが作用した可能性を示す観測を含みます。closed後は後続のCANCEL_REQUEST send invocationもnew cancel attemptも禁止します。結果未達、timeout、restartだけでは再openせず、transaction terminalまで`PENDING_REMOTE_FENCE`です。
- BearerがWOULD_BLOCKを返したときだけ、同じattempt/bindingとdefinite no-accept observationを`WOULD_BLOCK_RETRYABLE`へFULL commitできます。そのcommitが失敗/unknownならINVOKED_CLOSEDを維持します。したがって`controller.after_cancel_bearer_send`直後のcrash、Port result observation commit前crash、restartのいずれでもaccepted/unknown requestを重送しません。
- ControllerでApplication attemptがまだ作られていなければ、local dispatch fenceをFULL commitして`FENCED_BEFORE_DISPATCH / CANCEL_FENCED_BEFORE_DISPATCH`です。Application delivery可能性が一度でも生じた後は、cancel attempt/recordをFULL commitしてからforward `CANCEL_REQUEST`を送り、同期APIは`PENDING_REMOTE_FENCE / CANCEL_PENDING_REMOTE_FENCE`を返します。
- Endpointは`ABSENT`または`INBOX_COMMITTED`でcallback用`DELIVERY_STARTED` marker未commitの場合だけ、cancel tombstoneとdispatch fenceをFULL commitし、reverse `CANCEL_RESULT=FENCED_BEFORE_DISPATCH`をcache/sendします。
- Private Domain StoreではAPPLICATIONより先のcancel ownerをO(1)で再発見するため、attempt IDを含まないlogical delivery keyのprivate DELIVERY rootを物理作成します。これはApplication effectやpublic Deliveryの存在を意味せず、`creation_kind=CANCEL_FIRST / CANCEL_TOMBSTONE_ONLY`として本節のsemantic `ABSENT + cancel tombstone`へprojectします。後着APPLICATIONはfull bindingを照合して同じrootへattachしますが、inbox/Application ATTEMPT/callbackを作らずcached FENCED resultへ収束します。
- Endpointが`DELIVERY_STARTED`、active/expired token、result/Disposition、`RECOVERY_REQUIRED`、またはeffect possibilityを一度でも記録済みならeffectを取り消さず、cached `CANCEL_RESULT=TOO_LATE_EFFECT_POSSIBLE`を返します。duplicate same cancel attempt/bindingはcached resultを再送し、application callbackを追加で呼びません。
- Controllerで同じlogical timestampのvalid required Receiptとdurable-ingress済みCANCEL_RESULTが競合した場合はReceiptを先にreduceします。FENCED resultは`CANCELLED_BEFORE_EFFECT`、TOO_LATEは新attemptをfenceしたままevidence/deadlineを待ち、evidence closeまで不明なら`OUTCOME_UNKNOWN`です。Cancel result未達だけでno-effectを主張しません。
- Cancel record/resultはtransaction terminal retentionまで保持します。Repeated public `ninlil_cancel_request()`は新attemptを作らず、persist済みcurrent cancel kindを返します。Transactionが先にterminalなら`ALREADY_TERMINAL`です。

Cancelのledger/result precedenceと全fieldは次のclosed matrixです。Validation error、wrong role/family、NOT_FOUNDでは前記どおりkind/reason/outcomeをall-zeroにします。

| Durable state at API linearization point | `kind` | `reason` | `current_outcome` |
| --- | --- | --- | --- |
| cancel recordなし、transactionはactive、local no-delivery fenceを今回FULL commit | `FENCED_BEFORE_DISPATCH` | `CANCEL_FENCED_BEFORE_DISPATCH` | `CANCELLED_BEFORE_EFFECT` |
| cancel recordなし、transactionはactive、remote cancel prepareを今回FULL commit | `PENDING_REMOTE_FENCE` | `CANCEL_PENDING_REMOTE_FENCE` | `NONE` |
| cancel recordなし、transactionがcancel callより先にterminal | `ALREADY_TERMINAL` | current transactionのpersist済みterminal reason | current transactionのpersist済みnon-zero terminal Outcome |
| persist済みcancel kind=`FENCED_BEFORE_DISPATCH` | `FENCED_BEFORE_DISPATCH` | `CANCEL_FENCED_BEFORE_DISPATCH` | `CANCELLED_BEFORE_EFFECT` |
| persist済みcancel kind=`PENDING_REMOTE_FENCE` | `PENDING_REMOTE_FENCE` | `CANCEL_PENDING_REMOTE_FENCE` | 同じread snapshotのcurrent transaction Outcome。Activeなら`NONE`、cancel以外で後からterminalならそのpersist済みterminal Outcome |
| persist済みcancel kind=`TOO_LATE_EFFECT_POSSIBLE` | `TOO_LATE_EFFECT_POSSIBLE` | `CANCEL_AFTER_EFFECT_POSSIBLE` | 同じread snapshotのcurrent transaction Outcome。Activeなら`NONE`、後からterminalならそのpersist済みterminal Outcome |

Persist済みcancel kindのlookupはcurrent terminal checkより先です。したがってcancel自身でfenceした後のrepeatは`ALREADY_TERMINAL`へ変わらず`FENCED_BEFORE_DISPATCH`、pending/too-late後に別inputでterminal化してもkind/reasonはpersist済み値を返し、`current_outcome`だけ同じdurable read snapshotを反映します。Cancel recordが存在しないterminal transactionだけが`ALREADY_TERMINAL`です。Matrix外のkind/reason/outcome組合せを返しません。

## 10. EventFact park、resume、discard

```c
#define NINLIL_EVENT_RESUME_INVALID          ((ninlil_event_resume_kind_t)0u)
#define NINLIL_EVENT_RESUME_RESUMED          ((ninlil_event_resume_kind_t)1u)
#define NINLIL_EVENT_RESUME_ALREADY_RESUMED  ((ninlil_event_resume_kind_t)2u)
#define NINLIL_EVENT_RESUME_NOT_PARKED       ((ninlil_event_resume_kind_t)3u)
#define NINLIL_EVENT_RESUME_ALREADY_RELEASED ((ninlil_event_resume_kind_t)4u)
#define NINLIL_EVENT_RESUME_ALREADY_DISCARDED ((ninlil_event_resume_kind_t)5u)
#define NINLIL_EVENT_RESUME_NOT_EVENT_FACT   ((ninlil_event_resume_kind_t)6u)
#define NINLIL_EVENT_RESUME_CONFLICT         ((ninlil_event_resume_kind_t)7u)
#define NINLIL_EVENT_RESUME_STALE_SPOOL_REVISION ((ninlil_event_resume_kind_t)8u)
#define NINLIL_EVENT_RESUME_LIMIT_EXHAUSTED ((ninlil_event_resume_kind_t)9u)
#define NINLIL_EVENT_RESUME_NOT_RESUMABLE   ((ninlil_event_resume_kind_t)10u)

#define NINLIL_RESUME_CONNECTIVITY_REMEDIATED ((ninlil_event_resume_reason_t)1u)
#define NINLIL_RESUME_CAPACITY_REMEDIATED     ((ninlil_event_resume_reason_t)2u)
#define NINLIL_RESUME_APPLICATION_REMEDIATED  ((ninlil_event_resume_reason_t)3u)
#define NINLIL_RESUME_OPERATOR_OVERRIDE       ((ninlil_event_resume_reason_t)4u)
#define NINLIL_RESUME_TEST                    ((ninlil_event_resume_reason_t)5u)

typedef struct ninlil_event_resume_request {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t operation_id;
    ninlil_id128_t actor_id;
    uint64_t expected_spool_revision;
    ninlil_event_resume_reason_t resume_reason;
    uint32_t reserved_zero;
    ninlil_bytes_view_t audit_metadata;
} ninlil_event_resume_request_t;

typedef struct ninlil_event_resume_result {
    NINLIL_STRUCT_HEADER;
    ninlil_event_resume_kind_t kind;
    ninlil_reason_t reason;
    ninlil_id128_t operation_id;
    uint64_t retry_cycle_id;
    uint64_t spool_revision;
} ninlil_event_resume_result_t;

#define NINLIL_EVENT_DISCARD_INVALID          ((ninlil_event_discard_kind_t)0u)
#define NINLIL_EVENT_DISCARD_DISCARDED        ((ninlil_event_discard_kind_t)1u)
#define NINLIL_EVENT_DISCARD_ALREADY_DISCARDED ((ninlil_event_discard_kind_t)2u)
#define NINLIL_EVENT_DISCARD_ALREADY_RELEASED ((ninlil_event_discard_kind_t)3u)
#define NINLIL_EVENT_DISCARD_NOT_EVENT_FACT   ((ninlil_event_discard_kind_t)4u)
#define NINLIL_EVENT_DISCARD_CONFLICT         ((ninlil_event_discard_kind_t)5u)
#define NINLIL_EVENT_DISCARD_STALE_SPOOL_REVISION ((ninlil_event_discard_kind_t)6u)

#define NINLIL_DISCARD_DEVICE_DECOMMISSIONED ((ninlil_event_discard_reason_t)1u)
#define NINLIL_DISCARD_INVALID_EVENT          ((ninlil_event_discard_reason_t)2u)
#define NINLIL_DISCARD_OPERATOR_OVERRIDE      ((ninlil_event_discard_reason_t)3u)
#define NINLIL_DISCARD_TEST_CLEANUP           ((ninlil_event_discard_reason_t)4u)

typedef struct ninlil_event_discard_request {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t operation_id;
    ninlil_id128_t actor_id;
    ninlil_id128_t expected_event_id;
    ninlil_digest256_t expected_content_digest;
    uint64_t expected_spool_revision;
    ninlil_event_discard_reason_t discard_reason;
    uint32_t acknowledge_required_receipt_absent;
    ninlil_bytes_view_t audit_metadata;
} ninlil_event_discard_request_t;

typedef struct ninlil_event_discard_result {
    NINLIL_STRUCT_HEADER;
    ninlil_event_discard_kind_t kind;
    ninlil_reason_t reason;
    ninlil_id128_t operation_id;
    ninlil_id128_t audit_clock_epoch_id;
    uint64_t audit_committed_at_ms;
    uint64_t spool_revision;
    uint32_t spool_released;
    uint32_t reserved_zero;
} ninlil_event_discard_result_t;
```

Event rules:

- EventFact admissionは`NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS`個のresume operation/audit/resultと、1個のdiscard operation/audit/resultに対するlogical fixed capacity slotをevent spool bytes内にreserveします。未使用slotのStorage recordはmaterializeしません。Management ledger reservationはchecked `8 * 256 + 512 = 2560` logical bytesです。Portable `EVENT_SPOOL_BYTES` admission costはexactly `payload.length + NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES`で、attempt detail/retry summary/cumulative summaryのphysical storage overheadを含めません。reservation不能ならadmitしません。成功operationのledger recordとlogical used capacityはevent terminal後もservice dedup retention終了まで保持し、silent eviction/reuseしません。
- `event_spool_revision`はadmission commitで1、spool lifecycle、attempt/retry state、new evidence material/Receipt/custody、resume/discardを意味的に変える各FULL commitでchecked incrementします。Exact duplicate Receiptはdiagnostic duplicate counterとsaturating record revisionだけを更新し、spool revisionを変えません。Non-terminal incrementが`UINT64_MAX - 1`へ達するcommitでは同時に`COUNTER_EXHAUSTED / PARKED_RETRY`へ移し、その後はrequired Receiptまたはdiscardのterminal commitだけがchecked +1してMAXへ進められます。
- Required Receipt/discard terminal commitはcurrent revisionを通常どおりchecked +1し、得たterminal revision `R`（通常は2以上、headroom端ではMAX）をretention cleanupまでabsorbingにします。Terminal化のたび常にMAXへjumpしません。Valid late evidenceはraw evidence/summary、late flag/count、latest evidence、saturating `record_revision`、late-evidence metricだけをFULL updateし、`event_spool_revision = R`を維持します。Exact duplicateもspool revisionを変えません。Late evidenceによってmanagement expected revisionを新たにstale化せず、terminal Outcome/reason/tombstone/payload releaseを変更しません。Terminal commit unknownのauthoritative解決前はlate evidenceをreduceしません。
- `NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE` attemptsを使い切ったEventFactは`PARKED_RETRY`へ入り、payload、event ID、idempotency mapping、custodyを保持します。
- Public `PARKED_RETRY` snapshotのreasonは常に`EVENT_RETRY_CYCLE_PARKED`です。`event_park_cause`は別軸で、通常の8-attempt exhaustion=`CYCLE_EXHAUSTED_TRANSIENT`、Application Bearer WOULD_BLOCK/UNAVAILABLE=`BEARER_UNAVAILABLE`、valid remote `CAPACITY_EXHAUSTED / NO_EFFECT_PROVEN` Disposition=`CAPACITY_UNAVAILABLE`、DENIEDやapplication/schema/authorization remediation=`APPLICATION_REMEDIATION`、counter headroomなし=`COUNTER_EXHAUSTED`です。Local admission resource不足、step budget不足、Storage failureをCAPACITY_UNAVAILABLE parkへ変換しません。PARKED以外とDesiredStateでは`NONE`です。
- attempt detailはcycleごと`NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE`件です。直近`NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS` cycleをsummaryとして保持し、それ以前はfixed cumulative summaryへ集約します。event record自体は削除しません。
- `PARKED_RETRY`はperiodic retry timerを持たず、通常のstepだけで新attemptを作りません。
- Namespaceのlatest Bearer stateが`available=1`、そのepochがEventのpersist済み`last_seen_availability_epoch`と`last_consumed_availability_epoch`の両方よりstrictly大きく、park causeが`CYCLE_EXHAUSTED_TRANSIENT`、`BEARER_UNAVAILABLE`、`CAPACITY_UNAVAILABLE`のいずれかなら、そのEvent ownerはcompleted summary、新retry cycle、attempt count=0、seen/consumed epoch、spool revisionを1つのFULL transactionでcommitしREADYへ戻せます。同じ/古いepochで2回resetしません。複数Eventのfan-outは11.0 schedulerでEventごとに分割し、namespace observationと全Eventを巨大な1 transactionへまとめません。
- `APPLICATION_REMEDIATION`と`COUNTER_EXHAUSTED`はavailability epochだけでresumeしません。前者はexplicit resume、後者はrequired Receiptまたはdiscardだけを許します。Known `resume_reason` 5値はaudit分類だけでpark causeとのmatching guardに使いません。`CONNECTIVITY_REMEDIATED`、`CAPACITY_REMEDIATED`、`APPLICATION_REMEDIATED`、`OPERATOR_OVERRIDE`、`TEST`のいずれも、`COUNTER_EXHAUSTED`以外の4 resumable causeを手動resumeできます。
- `ninlil_event_resume()`はPARKED_RETRYだけを手動再開します。well-formed requestに対するactive/terminal/wrong-family/stale/conflictはAPI errorではなく`NINLIL_OK`とexact result kindです。
- `ninlil_event_discard()`はENDPOINT owner threadだけで使用します。新しいdiscard mutationが可能なのはnon-terminal EventFactだけですが、retained terminal/released/discarded EventFactへのwell-formed callもledger replayまたは`ALREADY_RELEASED` / `ALREADY_DISCARDED` semantic resultとして受理します。
- 両management APIはABI/null/request syntax、owner thread、re-entryを先に検証します。Runtime roleが`ENDPOINT`でなければtransaction lookupをせず`NINLIL_E_UNSUPPORTED`、result kindは`INVALID`、他fieldはzeroです。
- Endpoint storage namespaceにtransaction IDが存在しない、またはdedup/terminal retention cleanup済みなら`NINLIL_E_NOT_FOUND`です。result kindは`INVALID`、operation/cycle/revision/audit/flagを含む他fieldはzeroで、operation ledger/tombstoneを作りません。
- Existing DesiredStateCommand transactionは「unknown」ではなくwrong family semantic resultです。well-formed resume/discardは`NINLIL_OK + NOT_EVENT_FACT + EVENT_FACT_IMMUTABLE`を返し、request operation IDだけをechoし、cycle/revision/audit/flagはzeroです。Existing retained EventFactは現在stateがterminal/released/discardedでも以下のledger-first semantic reducerへ入ります。
- resumeはnon-zero operation/actor ID、known resume reason、exact expected spool revision、1〜128 byte audit metadataがrequiredです。Unseen operationの成功commitは初回callerへ`RESUMED`を返す一方、同じatomic ledger entryへcanonical replay result `ALREADY_RESUMED`（reason `NONE`、同じoperation ID、commit後retry cycle ID/spool revision）をpersistします。same operation ID/same request digestの以後のcallは、eventの現在state/revision/release状態にかかわらずこのstored replay resultをexactly返し、`RESUMED`を再返却せずcycleを2回resetしません。same operation ID/different digestは`RESUME_CONFLICT`、revision mismatchはunseen operationだけ`STALE_SPOOL_REVISION`です。8個のdistinct successful resume operationを使用後、9個目のunseen IDは`RESUME_LIMIT_EXHAUSTED / CAPACITY_EXHAUSTED`でstate/revisionを変えません。既存8 IDのreplayは引き続き可能です。
- discardはnon-zero operation/actor/event ID、matching SHA-256 content digest、known discard reason、`acknowledge_required_receipt_absent == 1`、exact expected spool revision、1〜128 byte audit metadata、trusted clockがrequiredです。Unseen operationの成功commitは初回callerへ`DISCARDED`を返し、同じatomic ledger entryへcanonical replay result `ALREADY_DISCARDED`（同じreason、operation ID、audit epoch/time、commit後spool revision、`spool_released == 1`）をpersistします。
- Runtimeはevent ID、transaction ID、operation、actor、reason、metadata、timestamp、content digest、highest Receipt、retry counters、terminal Outcome、DISCARDED tombstone、payload/spool eraseを1つのFULL transactionへcommitします。
- commit成功後だけin-memory spool reservationを解放し、transactionを`FAILED_DEFINITIVE / OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT`として公開します。
- commit失敗/unknown時はspoolを解放せず、discard resultを成功にしません。
- valid required Receiptとdiscardが同じlogical timeならReceiptを先にFULL commitし、discard resultは`ALREADY_RELEASED`です。discard commit後のReceiptはlate evidenceで、payloadを復元しません。

Management guard precedence:

1. ABI/null/syntax、role、transaction lookupを上記順で検証します。Missing/retention-expiredはAPI NOT_FOUND、existing wrong familyはsemantic NOT_EVENT_FACTで終了します。
2. Existing EventFactではResume/discard両ledgerからoperation IDを、current Event state、release/discard tombstone、retry cycle、expected/current spool revisionより先にlookupします。同じoperation kind + same canonical request digestがあれば、それらが後で変わっていてもstored canonical replay result `ALREADY_RESUMED` / `ALREADY_DISCARDED`を全field exactで返します。初回success kind `RESUMED` / `DISCARDED`を保存結果として再返却しません。
3. Operation IDが存在してdigestまたはoperation kindが違えば、resumeは`RESUME_CONFLICT`、discardは`DISCARD_CONFLICT`です。current state/revisionを評価しません。
4. Unseen operationだけcurrent state/cause（PARKED/RELEASED/DISCARDED/wrong family等）を評価します。PARKEDかつcause=`COUNTER_EXHAUSTED`なら`NOT_RESUMABLE`で終了します。他のresumable PARKEDだけexpected spool revision、次にresume ledger limitを評価し、known resume reasonとpark causeのmatching判定は行いません。
5. Storage commit unknown後のsame operation retryも2〜3の規則で、0回またはexactly 1回のmutationへ収束します。

Unseen operationは4のcurrent state/revision判定前にTargeted management linearizationのtrusted clock/catch-upを実行します。Catch-upでEventがPARKED/RELEASED/terminalへ進んだ場合、その新state/revisionに対してresume/discard guardを評価します。Ledger replay/conflictはclock call 0のままです。

Result field rules:

- Resume初回成功`RESUMED`とそのstored replay `ALREADY_RESUMED`はreason `NONE`で、operation ID、retry cycle ID、spool revisionは同じ成功commit値です。`NOT_PARKED`はreason `NONE`、`NOT_RESUMABLE`は`COUNTER_EXHAUSTED`、`ALREADY_RELEASED`は`REQUIRED_EVIDENCE_MET`、別operationから既にdiscard済みなら`ALREADY_DISCARDED / OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT`、`NOT_EVENT_FACT`は`EVENT_FACT_IMMUTABLE`、conflict/staleは同名reason、`LIMIT_EXHAUSTED`は`CAPACITY_EXHAUSTED`です。Unseen `NOT_RESUMABLE`はrequest operation IDと評価時のcurrent retry cycle/spool revisionをechoし、state/revision/ledger/resource/metricsを変更しません。
- Discard初回成功`DISCARDED`とそのstored replay `ALREADY_DISCARDED`は`OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT`で、operation ID、audit epoch/time、spool revision、`spool_released == 1`は同じ成功commit値です。別operationより先にrequired Receiptでrelease済みなら`ALREADY_RELEASED / REQUIRED_EVIDENCE_MET`、`NOT_EVENT_FACT`は`EVENT_FACT_IMMUTABLE`、conflict/staleは同名reasonです。
- Discard `DISCARDED`/`ALREADY_DISCARDED`だけ、persist済みnon-zero `audit_clock_epoch_id`と同epochの`audit_committed_at_ms`を返します。他kind/API errorでは両fieldをzeroにします。時刻0はvalidなのでepoch IDの有無でpresenceを判定します。
- well-formed management callは全semantic kindでrequest `operation_id`をechoします。Unseen operationのsemantic resultは評価時のcurrent値、初回successful resume/discardはatomic commitでspool revisionを1 checked incrementした値を返します。`ALREADY_RESUMED` / `ALREADY_DISCARDED` replayはcurrent値へ更新せずstored successful commit値を返します。存在しない/wrong family/API errorではcycle/revisionを0にします。
- `spool_released == 1`はdiscard kind `DISCARDED`または`ALREADY_DISCARDED`だけです。`ALREADY_RELEASED`はrequired Receiptによるreleaseなので、discardによるreleaseを示すこのflagは0です。

Management request digestはC struct memoryをhashしません。すべてのinteger/lengthはunsigned big-endian、IDは16 bytesをそのまま、metadataは`u32 length || exact bytes`です。ABI header、reserved field、pointer値は含めません。

```text
resume_request_digest = SHA-256(
    ASCII("NINLIL-M1A-EVENT-RESUME")
    || transaction_id[16] || operation_id[16] || actor_id[16]
    || expected_spool_revision_u64 || resume_reason_u32
    || metadata_length_u32 || metadata)

discard_request_digest = SHA-256(
    ASCII("NINLIL-M1A-EVENT-DISCARD")
    || transaction_id[16] || operation_id[16] || actor_id[16]
    || expected_event_id[16]
    || expected_content_digest_algorithm_u16
    || expected_content_digest_bytes[32]
    || expected_spool_revision_u64 || discard_reason_u32
    || acknowledge_required_receipt_absent_u32
    || metadata_length_u32 || metadata)
```

## 11. Step、capacity、metrics

```c
typedef struct ninlil_step_budget {
    NINLIL_STRUCT_HEADER;
    uint32_t max_ingress_messages;
    uint32_t max_callbacks;
    uint32_t max_state_transitions;
    uint32_t max_bearer_sends;
} ninlil_step_budget_t;

typedef struct ninlil_step_result {
    NINLIL_STRUCT_HEADER;
    uint32_t ingress_processed;
    uint32_t callbacks_invoked;
    uint32_t state_transitions;
    uint32_t bearer_sends;
    uint32_t transactions_terminalized;
    uint32_t events_parked;
    uint32_t more_work;
    uint32_t has_next_wake;
    ninlil_id128_t next_wake_clock_epoch_id;
    uint64_t next_wake_at_ms;
    ninlil_runtime_health_t health;
    ninlil_reason_t degraded_reason;
    uint32_t reserved_zero;
} ninlil_step_result_t;

#define NINLIL_HEALTH_OK                   ((ninlil_runtime_health_t)1u)
#define NINLIL_HEALTH_DEGRADED             ((ninlil_runtime_health_t)2u)
#define NINLIL_HEALTH_FATAL                ((ninlil_runtime_health_t)3u) /* M1a reserved; never generated */

#define NINLIL_RESOURCE_SERVICE            ((ninlil_resource_kind_t)1u)
#define NINLIL_RESOURCE_TRANSACTION        ((ninlil_resource_kind_t)2u)
#define NINLIL_RESOURCE_TARGET             ((ninlil_resource_kind_t)3u)
#define NINLIL_RESOURCE_OUTBOX_BYTES       ((ninlil_resource_kind_t)4u)
#define NINLIL_RESOURCE_DELIVERY           ((ninlil_resource_kind_t)5u)
#define NINLIL_RESOURCE_EVENT_SPOOL_COUNT  ((ninlil_resource_kind_t)6u)
#define NINLIL_RESOURCE_EVENT_SPOOL_BYTES  ((ninlil_resource_kind_t)7u)
#define NINLIL_RESOURCE_RESULT_CACHE       ((ninlil_resource_kind_t)8u)
#define NINLIL_RESOURCE_EVIDENCE           ((ninlil_resource_kind_t)9u)
#define NINLIL_RESOURCE_INGRESS            ((ninlil_resource_kind_t)10u)
#define NINLIL_RESOURCE_DEFERRED_TOKEN     ((ninlil_resource_kind_t)11u)

typedef struct ninlil_capacity_entry {
    NINLIL_STRUCT_HEADER;
    ninlil_resource_kind_t kind;
    uint32_t reserved_zero;
    uint64_t limit;
    uint64_t used;
    uint64_t reserved;
    uint64_t high_water;
    uint64_t capacity_epoch;
} ninlil_capacity_entry_t;

typedef struct ninlil_capacity_snapshot {
    NINLIL_STRUCT_HEADER;
    ninlil_capacity_entry_t *entries;
    uint32_t entry_capacity;
    uint32_t entry_count;
} ninlil_capacity_snapshot_t;

typedef struct ninlil_metrics_snapshot {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t metrics_epoch_id;
    ninlil_id128_t started_clock_epoch_id;
    uint64_t started_at_ms;
    uint64_t submission_calls;
    uint64_t admitted_ready;
    uint64_t already_admitted;
    uint64_t rejected;
    uint64_t idempotency_conflicts;
    uint64_t transactions_satisfied;
    uint64_t transactions_expired;
    uint64_t transactions_failed_definitive;
    uint64_t transactions_outcome_unknown;
    uint64_t events_parked;
    uint64_t events_resumed;
    uint64_t events_discarded;
    uint64_t late_evidence;
    uint64_t duplicate_logical_delivery;
    uint64_t application_callback_invocations;
    uint64_t reconcile_invocations;
    uint64_t delivery_token_timeouts;
    uint64_t storage_failures;
    uint64_t bearer_would_block;
} ninlil_metrics_snapshot_t;
```

### 11.0 Runtime step scheduler and clock contract

`ninlil_runtime_step()`はvalidation/result zeroing後、次のcall orderを固定します。

1. `clock.now`をexactly 1回呼び、trusted non-zero epochの**step-entry sample**を得る。Failure/uncertainは他のClock/Bearer/Storage/callbackを呼ばずfirst errorで終了する。
2. Durable Recovery workをfixed recovery orderで1 micro-operationずつ処理し、barrierを空にする。Recoveryが残る、budget不足、またはerrorならBearer state/receive、application callback、sendへ進まず`more_work=1`またはexact errorで終了する。
3. `bearer.state`をexactly 1回pollする。Valid strictly larger epochを観測しstate-transition budgetがあれば`runtime.before_bearer_state_commit` / `after`間でnamespace availability observationをFULL commitする。Budget不足ならcommitせず、そのstepの後続workも実行せず`more_work=1`とする。Exact same epoch/flagとold epochはwrite 0、same epoch/different flagはprovider contract failureでfirst error。Temporary/invalid statusは5.4のclosed matrixへ従う。
4. この時点のdurable scheduler owner集合と各ownerのready candidate cutを固定する。後のingress copyやring mutationで同stepのcutへcandidateを追加しない。
5. **ring owner 1件、ingress 1件**の順にlaneを交互処理する。先に未訪問かつbudgetにfitするring ownerを最大1 micro-operation処理し、次にIngress preflightがfitすれば`receive_next`を最大1回呼ぶ。一方のlaneがempty/closed/unfitでも他方を続行し、両laneが進めないかbudgetを使い切るまで繰り返す。
6. Work終了またはfirst error後、step-entry sampleだけを基準にmore-work/next-wakeとhealthを射影する。途中fresh sampleで新たにdueとなったtimerは次stepまでready setへ追加しない。

Ingress laneはremaining `ingress` 1 + `state transition` 1をpreflightでき、stage 3のvalid stateが`available=1`の場合だけ`receive_next`を呼びます。1 callがnon-EMPTY messageを返したら12章5.4のcopy/release規則で処理し、valid durable copyは次stepからreducer candidateになります。Invalid messageは規定どおりrelease/dropし、reserved state budgetを返します。`EMPTY`、`WOULD_BLOCK`、`UNAVAILABLE`でそのstepのIngress laneを閉じ、DENIED/contract faultはfirst errorでstep全体を停止します。Ingress budgetを使い切った後にEMPTY確認用の余分なcallを行いません。Ring laneを毎round先に試すためcontinuous ingressが既存ownerをstarveせず、new ingressを同stepへ割り込ませないためtraceがprovider queue timingに依存しません。

Step-entry sampleはdue判定、same-time priority、scheduler ready set、通常deadline/timer guard、next wakeへ共有します。次のsafety boundaryだけfresh `clock.now`を追加でexactly 1回呼びます。

- `on_delivery`用DELIVERY_STARTED/token commitの直前。Fresh sampleでdeadline/epoch/token expiryを再検査し、commit後すぐcallbackへ入る。
- 各Tx Gate `acquire`の直前。Permit requestへそのfresh sampleを渡し、sendまで別clock callを挟まない。
- `on_reconcile`が`RETRY_LATER`を返した直後、internal retry timer commit前。

Fresh call順は選択済みmicro-operationの上記位置どおりです。Failure、UNCERTAIN、epoch change/regressionではそのeffect/callback/gate/timerを実行せずclock causeをaddし、**first errorでstepを停止**します。既commit済みwork/counterはrollbackせず、残workがあれば`more_work=1`、`has_next_wake=0`/wake fields zeroです。Normal Bearer/TxGate temporary statusとsemantic rejectionはfirst API errorではなくclosed reducer inputです。複数faultをscriptしても最初に観測したnon-semantic API errorだけをreturnし、later Port/callbackへ進みません。

Ready workは、mutableなstate/work kind/revisionではなくdurableな**scheduler owner**でround-robinします。Namespaceは次の3 counterとcursorをpersistし、new namespaceでは全て0です。

- `last_assigned_scheduler_owner_sequence`: new logical root ownerへ割り当てた最大sequence
- `last_visited_scheduler_owner_sequence`: round-robin cursor
- `last_assigned_ordered_input_sequence`: durable reducer inputへ割り当てた最大sequence

New ownerを作るのは、new origin transaction、初見inbound APPLICATION Delivery、APPLICATIONより先に届いた初見cancel tombstoneだけです。First creation FULL commitで`last_assigned_scheduler_owner_sequence + 1`をchecked計算し、non-zero immutable `scheduler_owner_sequence`とcounterをatomic保存します。Valid Receipt/Disposition/Custody/CancelResult、duplicate APPLICATION/CANCEL_REQUEST、public management inputはcopy/lookup時に既存transaction/Delivery/tombstone ownerへattachし、新ownerを作りません。Well-formed reverse messageに既存ownerがなければdurable positive inputへせずbounded invalid drop、reply 0です。Retry、callback、reverse reply、terminal、retentionは元ownerを継承します。Runtime recoveryとnamespace Bearer state observationはring前stageでownerを持ちません。

Every durable ingress/management inputは既存/new ownerにかかわらず`last_assigned_ordered_input_sequence + 1`をcopy/mutation FULL commitへ含めます。Ordered-input counterがMAXなら新しい順序付きinputを作れないため`receive_next`を呼ばず、new management mutationもfail closedします。Owner counterがMAXでも既存ownerへbindingできるingress/replayは継続し、新rootだけをno-reply block/dropします。New origin admissionはidempotency lookup後、provider/entropy/reservation前にtransaction sequence→scheduler owner sequenceの順でheadroomを検査し、どちらかMAXなら`REJECTED / COUNTER_EXHAUSTED / RETRY_OPERATOR_ACTION / delay 0`です。Counter、owner、input/admission record、mapping/quota/reservationは各規定FULL commitでall-or-none、wrap/reuse/restart resetは禁止です。

選ばれたowner内では、step-entry epochと異なるdurable inputを時刻比較せずordered-input sequence順のRecovery Fenceへ回し、旧epoch timerをringへ出しません。Current epoch candidateは**logical time昇順**、exact same epoch/timeのときだけsemantic priority、work class、durable input sequence、target bytes、work kind、tie ID/generationの順で比較します。Clockを要しないready stateのlogical timeはstep-entry sampleです。後時刻の高priority inputが先時刻のdeadlineを追い越さず、same-timeだけ13章priorityを適用します。

```text
logical_time_u64_big_endian
semantic_priority_u8
work_class_u8
durable_input_sequence_u64_big_endian   // reducer input以外はUINT64_MAX
target_identity_record[100]             // §14 canonical target record。対象なしはall-zero
work_kind_u32_big_endian
tie_identity[16]                         // 表のID。該当なしはall-zero
tie_generation_u64_big_endian            // 表のgeneration/stage。該当なしは0
```

M1a work kindは次のclosed setです。Kind 1のpriorityだけ13章inputごとの0〜10、他は表のfixed値です。同じowner/kindのeligible cleanup recordは1 atomic groupへまとめ、複数candidateへ分裂させません。Event cycle summary/cumulative compactionはattempt-timeout/park/availability/manual-resumeの該当FULL commitに含め、独立work kindを作りません。

| kind | priority | class | Name | `tie_identity` / `tie_generation` |
| ---: | ---: | ---: | --- | --- |
| 1 | dynamic | 1 | `DURABLE_REDUCER_INPUT` | zero / 0。ordered input sequenceでtie-break |
| 2 | 8 | 1 | `AVAILABILITY_CONSUME` | zero / availability epoch（M1a bearerはRuntimeごとに1つ） |
| 3 | 5 | 2 | `COMMAND_EFFECT_DEADLINE` | zero / 0 |
| 4 | 6 | 2 | `COMMAND_EVIDENCE_CLOSE` | zero / 0 |
| 5 | 7 | 2 | `ATTEMPT_RECEIPT_TIMEOUT` | attempt ID / 0 |
| 6 | 9 | 2 | `INTERNAL_RETRY_DUE` | current attempt ID、未作成ならzero / next attempt index |
| 7 | 4 | 2 | `DELIVERY_TOKEN_TIMEOUT` | delivery context ID / token generation |
| 8 | 8 | 2 | `RECONCILE_DUE` | delivery context ID / reconcile retry generation |
| 9 | 9 | 3 | `DELIVERY_CALLBACK` | delivery context ID / next token generation |
| 10 | 8 | 3 | `RECONCILE_CALLBACK` | delivery context ID / reconcile retry generation |
| 11 | 9 | 4 | `APPLICATION_ATTEMPT_PREPARE` | zero / next attempt index |
| 12 | 9 | 4 | `APPLICATION_SEND` | attempt ID / 0 |
| 13 | 3 | 4 | `CANCEL_ATTEMPT_PREPARE` | zero / 0 |
| 14 | 3 | 4 | `CANCEL_REQUEST_SEND` | cancel attempt ID / 0 |
| 15 | 10 | 5 | `RECEIPT_REVERSE_SEND` | source attempt ID / evidence stage numeric value |
| 16 | 10 | 5 | `DISPOSITION_REVERSE_SEND` | source attempt ID / disposition kind numeric value |
| 17 | 10 | 5 | `CUSTODY_ACCEPTED_REVERSE_SEND` | source attempt ID / 0 |
| 18 | 10 | 5 | `CANCEL_RESULT_REVERSE_SEND` | cancel attempt ID / cancel result kind numeric value |
| 19 | 10 | 6 | `RETENTION_BASIS_UPDATE` | zero / retention kind 1=terminal, 2=result/disposition/token, 3=observation |
| 20 | 10 | 6 | `TERMINAL_RETENTION_CLEANUP` | zero / 0。transaction/target/evidence/idempotency/attempt indexを1 group |
| 21 | 10 | 6 | `RESULT_TOKEN_RETENTION_CLEANUP` | zero / 0。result/disposition/token/cancel cacheを1 group |
| 22 | 10 | 6 | `OBSERVATION_RETENTION_CLEANUP` | zero / 0。bounded observationsを1 group |

`target_identity_record`は14章canonical-submission-v1のexact 100-byte immutable target recordです。Runtime-local/no-target cleanupだけall-zeroを使います。Class/priority、absence sentinel、ID/generationが表と違う、record revision/pointer/address/container/hash iteration/issuer申告時刻をkeyに使う、異なるepoch IDのbytesを大小比較する実装はcontract failureです。

Ring順はowner sequence昇順です。Stage 4 cutをpersist済みcursorよりstrictly大きいownerから開始し、末尾後は先頭へ1回wrapします。同じownerは1 stepで最大1 micro-operation、ring中のnew owner/candidateは次stepです。Budget不適合ownerはskipし、fit owner 0ならcursor不変/`more_work=1`です。Cursorは「完了」でなく訪問済みfairness markerで、exact commit placementは次です。

| Micro-operation | `last_visited_scheduler_owner_sequence`を含める唯一のFULL commit |
| --- | --- |
| reducer、timer、attempt prepare、availability consume、retention/cleanup | そのsingle semantic commit |
| `on_delivery` | callback前のDELIVERY_STARTED success（kind9 phase1）。N+1不能は kind9 phase2 + `*_delivery_start_counter_exhausted_commit`（callback 0）。DEFERは追加FULL writeなし |
| remote cancel send | Bearer前のINVOKED_CLOSED gate commit |
| ordinary Application send | Bearer returnのsend observation commit |
| duplicate-safe reverse send | Bearer returnのreverse observation commit |
| `on_reconcile` | KNOWN/REDELIVER/RETRY_LATER/OUTCOME_UNKNOWN/recovery result commit |
| stale/no-op candidate | cursor-only FULL commit（state transition budget 1） |

1 micro-operationでcursor updateは最大1回です。各cursor-containing FULL groupだけがstate/cursor all-or-noneで、複数commit全体を1 transactionと偽装しません。COMMIT_UNKNOWNはそのgroupのauthoritative resolutionまでcursorを推測しません。削除済みcursorはuint64 upper-boundから再開します。On-delivery/cancelのcursor後crashはdurable claim/gate recoveryへ、ordinary/reverse sendのobservation前crashは下記same-attempt/duplicate-safe replayへ収束します。これによりcontinuous revision/work-kind mutationでも他ownerをstarveしません。

`ATTEMPT_PREPARED`はordinary Application sendのdurable pre-send gateです。Send micro-operationはbearer send 1 + state transition 1をreserveし、fresh clock→TxGateを経て、Gate OKならsame attempt ID / immutable messageをBearerへ1回渡し、return observation + cursorを1 FULL commitします。TxGate TEMPORARY/DENIED/contract fenceはsend reservationを返し、対応reducer state + cursorだけを1 FULL commitします。Send後/observation前crashではfresh permitを得て**同じattempt ID/bytesだけ**を再送でき、new attempt/entropy/budget消費は禁止です。Receiver persistent dedupでcallback/effectを重複させません。Observation COMMIT_UNKNOWN中は再送せず、recoveryでnon-commit確定した場合だけsame attemptを再送します。したがってApplicationはduplicate-safe at-least-once、remote cancel requestは既存INVOKED_CLOSED規則のconservative single-invocationです。

Callbackはowner threadを同期占有するため、application/providerがplatform-defined bounded time内にreturnするpreconditionです。`application_completion_timeout_ms`はcallbackのpreemption/watchdogではありません。長い非同期処理はcallbackから速やかに`DEFER`を返してtokenで完了し、callback内でblock/sleep/I/O待ちを続けません。

Retention recordはterminal transaction、result/disposition/token tombstone、bounded observationごとに`retention_duration_ms`、basis epoch/time、delete-at、basis-pending/overflow flagをdurably持ちます。

- Retention-starting FULL commitでtrusted local sampleがある場合、basisをそのsample、`delete_at_ms = checked(now_ms + duration)`とします。Cleanup eligibilityはexclusive retention end、すなわちsame epochで`now_ms >= delete_at_ms`です。`now == delete_at`は削除可能です。
- Trusted sampleがない/UNCERTAINならbusiness state/result commitを巻き戻さず`basis_pending=1`として保持し、cleanup/wakeを作りません。後のfirst trusted sampleでfull durationを開始するFULL commitまで削除禁止です。
- Checked addition overflowは`retention_overflow=1`をpersistしdelete-atをzero、cleanup/wake 0、health `COUNTER_EXHAUSTED`です。Wrap/saturating timestampや即時削除を行いません。
- Restartでsame epochならpersist済みbasis/delete-atを維持します。Clock epoch changeでは旧数値を比較せず、first trusted new-epoch sampleから**full original duration**を再基準化して延長します。短縮/旧epoch elapsed推測をしません。再基準commit failure/unknownでは旧recordを保持します。
- Cleanupは[17章](17-foundation-domain-store.md)のdurable planに従います。Unbounded ATTEMPT detail/indexだけをreuse fence付きbounded FULL batchで削除し、dedup/evidence/resource reservationとprimaryはFINALIZEの1 FULL transactionで削除/releaseします。Capacity blocked improvementが該当すればFINALIZEでepochを進めます。Planなしpartial cleanup、terminalより早いresult/evidence delete、untrusted-clock deleteは禁止です。

`terminal_retention_ms`はtransaction/target/idempotency/query/evidence、`result_cache_retention_ms`はreceiver result/disposition/token/cancel cache、`observation_retention_ms`はbounded diagnosticだけへ適用します。Service `required_dedup_window_ms`とのregistration guardを満たすため、cleanupは該当する最長required retentionより早く実行しません。

M1aが`ninlil_step_result_t.health`とmetrics/diagnosticへ生成するhealthは`OK`または`DEGRADED`だけです。`NINLIL_HEALTH_FATAL`はforward ABI reservationで生成しません。Unrecoverableに見えるcallback/Port/invariant failureも、規定のspecific API status、fail-closed state、`DEGRADED` healthへ収束させ、実装判断でFATALへ昇格しません。

### 11.1 Capacity accounting

`ninlil_capacity_snapshot()`はkind 1〜11をこの順でexactly 11件返します。roleで不使用のkindも`limit/used/reserved/high_water = 0`で省略しません。Snapshot全体は1つのlogical read snapshotです。

共通規則:

- `used`はsnapshot時点でcommit済み/liveなunit、`reserved`はadmission、callback、future evidence/attempt等へ確保済みだが未使用のunitです。reservationは成功経路の最初のeffect/callbackより前に取得し、commitまたはrollback/releaseでusedへ移すか解放します。
- 全entryでchecked `used + reserved <= limit`です。違反、underflow、予約なし消費は`STORAGE_CORRUPT`相当でfail closedします。
- `high_water = max(previous high_water, used + reserved)`で、`UINT64_MAX` saturating、wrapなしです。Capacity metadata、high-water、epoch、blocked flagはstorage namespace内でrestartを跨いでpersistします。既存namespaceを異なるresource limitで開くには後続migrationが必要で、M1aは`NINLIL_E_UNSUPPORTED`です。
- New storage namespaceは各kind `capacity_epoch = 1`、`high_water = 0`で開始します。そのkind不足によりworkを実際にreject/blockした時にpersistent blocked flagを立て、その後available unitが増えて同じclassのworkを再評価可能にしたrelease/recovery **FULL commit**でだけepochをstrict incrementし、flagをclearします。poll、reservation、使用増、無関係release、restart、同値snapshotでは増やしません。
- Blocked release時にepochが`UINT64_MAX`なら、business terminal/cleanupとresource `used/reserved` releaseを止めません。同じFULL transactionでrelease、`blocked=0`、epoch MAX維持、durable `COUNTER_EXHAUSTED` markerをcommitし、wrap/zero/rollbackをしません。以後そのresource kindを必要とするnew admission/workは`COUNTER_EXHAUSTED / RETRY_OPERATOR_ACTION`で拒否しますが、既存workのReceipt、terminalization、retention cleanup、resource releaseは継続します。MAX時もcapacity hook pairを通し、commit unknownはrelease/blocked/marker all-or-noneです。
- Capacity metadata 11 recordとそのFULL update journal headroomはnamespace初期化でfixed-size preallocateするplatform preconditionです。Block guardでflag=0なら、`runtime.before_capacity_epoch_commit` → blocked=1 metadata FULL commit → `runtime.after_capacity_epoch_commit`の成功後だけsemantic capacity rejection/blockを公開します。Flagが既に1ならwrite/hook 0で同じrejectionを返せます。Release時の`blocked=1 → blocked=0 + epoch+1`も同じhook pairを使い、hook contextのoperation kindを`BLOCK_SET`または`AVAILABILITY_RELEASE`へ固定します。
- Block-set metadata commitがBUSYなら元semantic rejectionを返さずAPI/stepを`NINLIL_E_WOULD_BLOCK`相当にし、NO_SPACEはpreallocated-headroom contract違反として`NINLIL_E_STORAGE_CORRUPT`、IO/CORRUPTは通常Storage error、COMMIT_UNKNOWNはnamespace fence/`NINLIL_E_STORAGE_COMMIT_UNKNOWN`です。Submission resultはINVALID/zero、inbound message/resultは未処理のまま保持し、capacity epochを進めません。Recoveryがblocked flagのauthoritative値を決めるまで「rejection済み」と推測しません。
- Bearer `availability_epoch`とは別domainです。Capacity epochはresource kind間でも相互比較しません。

`N = checked(max_nonterminal_transactions + max_retained_terminal_transactions)`として、limit/unitとlifecycleを固定します。Nまたは表中limit formulaのoverflowは`runtime_create = NINLIL_E_INVALID_ARGUMENT`で、saturating limitへ変換しません。

| Kind | Unit / limit | used | reserved | Reservation → release event |
| --- | --- | --- | --- | --- |
| `SERVICE` | durable semantic service-registry slot / `max_services` | persist済みunique namespace/service/revision binding。Volatile handle attachment数ではない | 初回registration中のslot | descriptor validation後→first registry commit rollback。M1aにunregisterなし、restartでusedを0へ戻さない |
| `TRANSACTION` | transaction lifecycle slot / `N` | non-terminal + retained terminal transaction | new admission slot。Command cancel record 1件を内包 | admission前→terminal retention cleanup |
| `TARGET` | concrete target slot / `checked(N * max_targets_per_transaction)` | transactionにcommit済みtarget | admission target roster | admission前→transaction retention cleanup |
| `OUTBOX_BYTES` | logical payload byte / `max_durable_outbox_payload_bytes` | required evidence未達でdurable outboxが保持するpayload bytes | staged Command payload/outbox bytes | admission前→required evidence/terminal payload release |
| `DELIVERY` | inbound delivery lifecycle slot / `max_nonterminal_deliveries` | INBOX_COMMITTED〜result/disposition/reconcile完了前 | ingress commit前のdelivery slot | durable ingress前→result/disposition/reconcile terminal commit |
| `EVENT_SPOOL_COUNT` | held EventFact 1件 / `max_event_spool_count` | HELD/attempt/retry/park中event | Event admission slot | grant評価後→required Receiptまたはdiscard commit |
| `EVENT_SPOOL_BYTES` | portable logical byte / `max_event_spool_bytes` | committed payload + 使用済みresume slot×256 + 使用済みdiscard slot×512 | admission staging中はpayload+2560 total、FULL admission後は未使用management slot（8×256 + 1×512） | FULL admissionでpayloadだけreserved→used、managementはreserved維持。各resume/discard successで該当slotだけreserved→used。Receipt/discard terminalでpayload usedとunused reservedを解放、使用済みaudit slot usedはdedup cleanupで解放 |
| `RESULT_CACHE` | cached result/disposition/token tombstone 1件 / `checked(max_result_cache_entries + max_retained_dispositions)` | retention中cache/tombstone | callback前のresult/disposition/tombstone slot | delivery開始前→result/dedup retention cleanup |
| `EVIDENCE` | evidence slot / `checked(N * max_targets_per_transaction * (max_evidence_per_target + 1))`。`+1`はtargetごとのfixed summary | commit済みsummary 1 + raw material slots | admissionで保証した未使用raw slots | admission前→raw/summaryともtransaction evidence retention cleanup。Terminal commitではunusedを解放しない |
| `INGRESS` | durable copied/unreduced Bearer message 1件 / `max_ingress_per_step` | ingress FULL commit済みで未reduceのmessage | receive copy FULL commit中の1件 | receive前→reducer commit/drop。step/restartでusedを0へ戻さない |
| `DEFERRED_TOKEN` | active delivery token 1件 / `max_deferred_tokens` | physical DELIVERY_STARTEDかつ`token_state=ACTIVE`（public DEFERRED_WAIT projectionを含む） | callback前token slot | delivery start前→complete/timeout/recovery invalidation commit |

Admission/callback/retryが複数kindを必要とする場合、全kindを決定的kind昇順でreserveし、途中失敗では逆順releaseしてapplication effect/callbackを開始しません。`reserved`を「storageに空きがありそう」という推測値にせず、Coreが所有するreservation recordだけを数えます。

各origin transaction/targetはadmission commitでEVIDENCE summary 1 slotを`used`、raw `max_evidence_per_target` slotsを`reserved`にします。New valid materialはraw空きがあれば1 slotだけreserved→used、raw上限後は既存summaryをatomic updateしslot数を変えません。Exact duplicateはsummary duplicate counter以外のmaterial、event spool revision、public late-evidence metricを増やしません。Terminal commit後もunused raw reservationとsummary/raw usedを保持し、Transaction/evidence retention cleanupでだけ全releaseします。

このlate-evidence保証はlogical counterだけでなくphysical Storageをadmission時に確保する契約です。Coreはsummary 1件とraw `L`件を、occupancy/metadata、最大128-byte evidence inline領域、digest/time/issuer/bindingを含む**最大encoded sizeのfixed-size cell**としてadmission FULL transaction中にmaterializeします。Unused raw cellも実valueを占有し、後のinsert/updateでvalue lengthやentry countを増やしません。Storage implementationは1 evidence-cell replacementを完了できるfixed journal/commit headroomをnamespace initializationでpreallocateし、通常workへ貸し出しません。Initial materializationまたはheadroomを実現できなければadmissionをcapacity/storage errorで拒否し、`local_capacity_reserved`をtrueにしません。このpreconditionが成立したadmitted transactionだけ、後のunrelated Storage full状態でもreserved raw cellまたはsummary replacementへlate materialをcommitできます。Media I/O/corruption/commit-unknownは通常のStorage failure規則であり、成功を偽装しません。

SERVICE/INGRESSを含む全capacity metadataはdurableです。First service registry commitはSERVICE used/high-water/blocked metadataを同じFULL transactionで更新し、callback/handle attachだけでは変えません。Bearer messageはprovider bufferをreleaseする前にINGRESS slot、exact message copy、durable ingress sequence、INGRESS used/high-waterを1つのFULL transactionへcommitし、reducer commit/dropと同じFULL transactionでslotをreleaseします。Commit失敗/unknownではprovider ownership/copy recovery規則へ従い、step endやRuntime restartだけでSERVICE/INGRESS used/high-water/epoch/blocked flagをresetしません。

`EVENT_SPOOL_BYTES`は実装間比較可能なportable accountingであり、attempt record、4 recent cycle summary、cumulative summary、storage key/index/padding/CRC等のphysical bytesを加算しません。それらはStorage Port `capacity.max_bytes/used_bytes`で別に管理します。Live中は`used + reserved = payload.length + 2560`を保ち、management operation successは該当fixed slotをreservedからusedへ移すだけでtotal/high-waterを増やしません。Terminal時のretained portable used bytesはchecked `successful_resume_operation_count * 256 + (discard_operation_committed ? 512 : 0)`だけで、reservedは0です。

### 11.2 Step budget accounting

`ninlil_runtime_step()`はresult counterをcall開始時0にし、次のunit/increment pointだけを数えます。Public management/submit/query APIがstep外で行ったworkは含めません。

| Counter | Exact unit | Increment point |
| --- | --- | --- |
| `ingress_processed` | Bearer `receive_next`が返したnon-EMPTY message 1件をCoreがconsumeし`release_received`したこと | release直後に1。Valid ingress、duplicate、invalid/drop、copy/capacity failureを含む。EMPTY/Port errorは0 |
| `callbacks_invoked` | `on_delivery`または`on_reconcile`へのactual function entry 1回 | callbackへcontrolを渡す直前に1。Callback前commit failureは0 |
| `state_transitions` | runtime_stepが開始した1 Storage `FULL` transactionのcommit OKによりCore-owned durable bytes/stateが1つ以上変化 | commit OK観測直後に1。Multi-record/複数field atomic groupも1、read/no-op/rollback/definite failure/COMMIT_UNKNOWNは0 |
| `bearer_sends` | Bearer `send` actual invocation 1回 | Port return直後に1。OK/WOULD_BLOCK/UNAVAILABLE/DENIED/LOST_UNKNOWN/CORRUPTを同じ1、TxGate denial/send前failureは0 |
| `transactions_terminalized` | このstepでauthoritative projectionがnon-terminalからterminalへ初めて変化したtransaction 1件 | 対応FULL commit OK後に1。既存terminal/replay/recovery readは0 |
| `events_parked` | このstepでEventFactがnon-PARKEDから`PARKED_RETRY`へ初めて変化した1件 | 対応FULL commit OK後に1。同じpark replay/既存PARKEDは0 |

`transactions_terminalized`と`events_parked`はbudget categoryではなくstate transitionの分類counterです。同じFULL commitは`state_transitions`を1増やし、該当する分類counterも1増やせますが、1 transaction/eventを同じtransitionで重複加算しません。COMMIT_UNKNOWNが実際にapplyされていても当該stepでは0で、later recovery readだけでも過去counterを再構成しません。

External side effect前のbudget preflightは次のworst-case reservationです。Reservation自体はcounterを増やさず、未使用分は同じstepへ返します。

| Scheduler micro-operation | Required remaining budget before start | Boundary rule |
| --- | --- | --- |
| receive one ingress | ingress 1 + state transition 1 | valid messageのdurable ingressを保証できない限り`receive_next`を呼ばない。EMPTY/invalidでcommit不要ならstate reservationを返す |
| timer/reducer/recovery/cleanup durable mutation | state transition 1 | 1 FULL groupをpartial stagingせず、budget不足なら開始しない |
| `on_delivery` dispatch | callback 1 + state transitions 2 | 1つ目はcallback前DELIVERY_STARTED、2つ目はCOMPLETE/FATAL/contract result。DEFERなら**追加durable writeなし**で2つ目のstate-transition reservationを同一stepへ返す。Callback return resultをvolatileに次stepへ持ち越さない |
| `on_reconcile` dispatch | callback 1 + state transition 1 | KNOWN/result/recovery actionの最大1 FULL groupを同じstepで完了。commit不要actionはreservationを返す |
| ordinary Bearer send | bearer send 1 + state transition 1 | send outcomeをdurably観測できるheadroomなしにPortを呼ばない |
| remote cancel request send | bearer send 1 + state transitions 2 | pre-send gate close + post-return observation/WOULD_BLOCK reopenのheadroomを先に確保 |

1 logical operationが複数rowを不可分に必要とする場合はcategoryごとにchecked sumを予約します。Durable boundaryで分割可能なattempt prepare→later send、result commit→later reply send等は別micro-operationです。どれか不足ならPort/callback/storage side effect 0でworkをqueueに残し、`more_work = 1`です。このpreflightにより同じinitial state/budget/Port scriptのstep countersとnext durable boundaryが実装間で一致します。

- budget各fieldの0は「そのcategoryのworkをこのstepでは0件」にする明示値です。non-zeroは対応するruntime config上限以下でなければ`NINLIL_E_INVALID_ARGUMENT`で、silent clampしません。ingress、callback、state transition、Bearer sendに同じ規則を適用します。
- Runtimeは1つのlogical operationがいずれかの残budgetを超える場合、そのoperationを部分実行せず次stepへ残します。全field 0もvalidで、counterは0、pending workがあれば`more_work = 1`です。
- `more_work`は同じvirtual timeで処理可能なworkが残る場合1です。
- `more_work == 1`はcurrent logical timeで直ちにもう一度stepすべきworkがあることを示します。`has_next_wake == 1`はdurable pending timerのうちcurrent trusted clock epochと一致する最早の**future** pointを`next_wake_clock_epoch_id/next_wake_at_ms`で返します。両flagは同時に1でもよく、callerはまずimmediate stepを行い結果を再取得します。
- correctness timerにはattempt Receipt timeout、internal retry-not-before、Command effect deadline/evidence close、delivery token expiry、reconcile retry、retention/cleanup dueを含みます。EventFact `PARKED_RETRY`だけではtimer wakeを生成しません。
- `has_next_wake == 0`ではepoch ID/timeをともにzero、1ではepoch ID non-zeroかつ`next_wake_at_ms > current now_ms`です。due-now timerはfuture wakeでなく`more_work`へ入れます。
- Caller/harnessは同じepochのabsolute pointへwakeをscheduleします。早くstepしてもよく、Runtimeは未到達timerを発火しません。clock uncertain、timer epoch mismatch、clock port failureではwake時刻を推測せず`has_next_wake = 0`、health/reasonへ`CLOCK_UNCERTAIN`を公開します。Platformはclock state/epoch変化自体でもRuntimeをwakeします。
- Capacity snapshot callerは`entry_capacity == 0`なら`entries == NULL`、non-zeroならpointer non-NULLかつ提供した**全entry_capacity要素**のABI headerを初期化します。Coreはsnapshot header/pointer/capacity、各provided entryのheaderをこの順で検証してからrequired count 11と比較します。1要素でもABI version/required struct sizeが不正なら`NINLIL_E_ABI_MISMATCH`、`entry_count = 0`で全entryを変更しません。
- Valid headerだがcapacity 11未満なら`NINLIL_E_BUFFER_TOO_SMALL`とrequired `entry_count = 11`を返し、entryを部分書込しません。capacity 11以上なら先頭11要素だけへexact orderで書き、`entry_count = 11`、余剰要素は変更しません。
### 11.3 Metrics and health

MetricsはRuntime create stage 9からdestroy fenceまでのobservability counterで、transaction journalの代替ではありません。各createはfreshly drawn non-zero `metrics_epoch_id`、全counter 0で始まり、restart時に旧counterを再構成しません。Metrics epochのstrict uniquenessは保証せず、Runtime/start sampleと一緒に解釈します。`started_clock_epoch_id`/`started_at_ms`はcreate stage 7のtrusted sampleへ固定し、後のepoch changeで書き換えません。

| Counter | Exact increment rule |
| --- | --- |
| `submission_calls` | Valid service handle、outer submission/result pointer+ABI header、owner/re-entry validationを通過した`ninlil_submit` invocationごとに1。以後のnested pointer/content API error、provider/Storage errorも含む。NULL/stale handle、wrong thread/re-entry、outer ABI mismatchは0 |
| `admitted_ready` / `already_admitted` / `rejected` / `idempotency_conflicts` | Public returnが`NINLIL_OK`かつ対応exact kindのとき各1。1 callで最大1 kind。API error/COMMIT_UNKNOWNはkind counter 0 |
| `transactions_satisfied` / `transactions_expired` / `transactions_failed_definitive` / `transactions_outcome_unknown` | このmetrics epochでauthoritative transactionがnon-terminalから対応Outcomeへ初めて移るFULL commit OKごとに1。CANCELLED_BEFORE_EFFECTはこの4 counter外。Existing terminal load/replayは0 |
| `events_parked` | Eventがnon-PARKED→PARKEDへFULL commit OKごとに1 |
| `events_resumed` | PARKED→READYのavailability resumeまたは初回explicit RESUMED commitごとに1。replayは0 |
| `events_discarded` | 初回DISCARDED audit/tombstone FULL commit OKごとに1。ALREADY replayは0 |
| `late_evidence` | terminal後に新しいvalid late evidence materialをraw insertまたはsummary updateへdurably commitしたとき1。Exact duplicateは0 |
| `duplicate_logical_delivery` | valid duplicate APPLICATIONをdurable identity/bindingで認識し、new callbackを抑止したmessageごとに1 |
| `application_callback_invocations` | `on_delivery` actual function entry直前に1 |
| `reconcile_invocations` | `on_reconcile` actual function entry直前に1 |
| `delivery_token_timeouts` | active token→expired/RECOVERY_REQUIRED FULL commit OKごとに1。late completion replayは0 |
| `storage_failures` | Published RuntimeのStorage Port callが`BUSY`、`NO_SPACE`、`IO_ERROR`、`CORRUPT`、`COMMIT_UNKNOWN`、`UNSUPPORTED_SCHEMA`、またはcontext上unexpectedなNOT_FOUND/BUFFER_TOO_SMALLを返すごとに1。Expected lookup miss/end/size probeとcreate前/destroy後は0 |
| `bearer_would_block` | Published Runtimeのactual Bearer `send` invocationが`NINLIL_BEARER_WOULD_BLOCK`を返すごとに1。Same cancel attempt retryも各Port returnを数える |

全counterは該当観測/commit OKの直後にchecked incrementし、`UINT64_MAX`でsaturate、wrapしません。Saturationはhealth/reducerを変えずsupport diagnosticだけです。`ninlil_metrics_snapshot()`は全fieldを1つのowner-thread logical snapshotとして返し、自身のcallではcounterを増やしません。

Runtime healthはactive degraded-cause multisetから導出します。Cause 0件なら`health = OK`かつ`degraded_reason = NONE`、1件以上なら`health = DEGRADED`かつ次priorityで最上位のnon-zero reasonを返します。`HEALTH_FATAL`は生成しません。

Lifecycle L1 pure reducerのhealth入力は次表の8 slotにclosedです。各slotはfree-form reasonでなくnon-negative reference countで、lowest-numberのnon-zero slotだけをprojectします。全slot zeroなら`OK/NONE`、1件以上なら`DEGRADED/該当reason`で、同priorityは最後のreferenceがclearされるまで残ります。Generic projectorはpublished Runtimeのhealth表示用にpriority 1/2も扱えます。Stage 9は別のpublish gateを必須とし、Stage 5 recovery completeかつpriority 1/2 zeroのときだけproject可能です。Stage 9へ渡すのはStage 5がdurable markerから再構成したreferenceだけで、Provider/clock/entropy/Bearer等のinstance-local causeはrestart時にcopyしません。

| Priority | Active cause / reason | Add / clear boundary |
| ---: | --- | --- |
| 1 | Storage corrupt/definite I/O / `STORAGE_IO` | failureでadd。successful reopen + schema/capacity/recovery scan完了で同causeをclear |
| 2 | unresolved commit unknown / `STORAGE_COMMIT_UNKNOWN` | unknown観測でadd。authoritative record resolutionでclear |
| 3 | callback/known-result contract fence / `CALLBACK_CONTRACT` | recovery marker commitでadd。該当deliveryのvalid reconcile terminal commitでclear |
| 4 | callback FATAL/application failure fence、Bearer receive/state denial / `APPLICATION_FAILED` | Durable callback markerはrecovery commitでaddし該当deliveryのvalid reconcile terminal commitでclear。Bearer denialは下表のinstance key規則 |
| 5 | origin provider permanent failure/invalid decision / `GRANT_PROVIDER_UNAVAILABLE` | API `DEGRADED + SUBMISSION_INVALID`でadd。後のvalid provider evaluationでclear。Temporary failureはaddせずAPI WOULD_BLOCK |
| 6 | clock permanent/uncertain/epoch fence / `CLOCK_UNCERTAIN` | unsafe clock observationでadd。trusted non-regressing sampleと全affected timer/token guard再評価後clear |
| 7 | non-recoverable counter headroom / `COUNTER_EXHAUSTED` | exhaustion commit/observationでadd。同Runtime instanceではclearしない |
| 8 | entropy exhaustion、Bearer/TxGate method fault、internal invariant fence / `OUTCOME_UNKNOWN` | 下表のdistinct source keyでadd/clear。Internal invariantは同Runtime instanceでclearしない |

Cause multisetのreferenceは観測回数でなく次のdistinct source keyです。同じkeyの反復failure/denialは1 reference、別keyは同priorityでも別referenceです。Instance-local keyはrestartへcopyせず、durable markerだけをStage 5で再構成します。

| Source key | Priority / durability | Add | Exact clear |
| --- | --- | --- | --- |
| `entropy.transaction_id` | 8 / instance | 1 transaction IDの4-draw exhaustion | 次のtransaction-ID allocationがvalid non-zero unique candidateを選択した時点。後続commit成否は問わない |
| `entropy.attempt_id` | 8 / instance | Application/cancel attempt IDの4-draw exhaustion | 次のattempt allocationがvalid non-zero unique candidateを選択した時点 |
| `tx_gate.acquire_fault` | 8 / instance | unknown status、invalid/partial decision、non-OK poison | 次のacquireがOK-valid、TEMPORARY-zero、DENIED-zeroのいずれかへ正規化された時点 |
| `bearer.send_fault` | 8 / instance | CORRUPT/unknown/invalid output shape | 同methodがknown non-CORRUPT status + exact valid output shapeを返す |
| `bearer.receive_fault` | 8 / instance | LOST_UNKNOWN/CORRUPT/unknown/non-OK poison | `OK + exact valid message`、EMPTY、WOULD_BLOCK、UNAVAILABLE、またはexact DENIED |
| `bearer.state_fault` | 8 / instance | EMPTY/LOST_UNKNOWN/CORRUPT/unknown/partial | `OK + exact valid state`、WOULD_BLOCK、UNAVAILABLE、またはexact DENIED |
| `bearer.receive_denied` | 4 / instance | exact receive_next DENIED | 同methodの`OK + exact valid message`、EMPTY、WOULD_BLOCK、UNAVAILABLE |
| `bearer.state_denied` | 4 / instance | exact state DENIED | 同methodの`OK + exact valid state`、WOULD_BLOCK、UNAVAILABLE |
| durable callback contract/application marker ID | 3/4 / durable | marker FULL commit/recovery発見 | そのmarkerにbindingしたvalid reconcile terminal commit |
| durable internal invariant marker ID | 8 / durable | marker FULL commit/recovery発見 | M1a clear operationなし |

Transaction entropy成功はattempt keyを、send成功はreceive/state keyをclearしません。Exact Bearer DENIEDは同method fault keyをclearした後、対応denial keyをaddします。Receive/state DENIEDはmessage/transactionへbindingできないためdurable marker、release、INGRESS、callback、reply、transaction mutationを作らず、step first errorは`NINLIL_E_DEGRADED`です。Send/TxGate semantic DENIEDはtransaction reducerだけへ作用しdenial health keyをaddしません。Bearer open DENIEDはRuntime publish前の`NINLIL_E_UNSUPPORTED`です。Business OutcomeやEFFECT_POSSIBLEはhealth keyのclearで反転しません。

同priority/causeは最後のdistinct source/marker解消までclearしません。複数causeが同時発生しても表のpriorityだけでcurrent `degraded_reason`を決め、発生順やhash iterationに依存しません。Higher cause解消時は次active reasonへ移り、全cause解消時だけOK/NONEへ戻ります。通常のAPI invalid/rejection、Bearer WOULD_BLOCK、business `OUTCOME_UNKNOWN` transactionだけではRuntime healthをDEGRADEDにしません。

Health counter自体を別journalへ二重保存せず、Stage 5 recovery scanがdurable source markersからactive multisetを再構成します。対象は未解決commit fence、Delivery `RECOVERY_REQUIRED`のpersist済みreason、namespace/transaction/cycle/resourceのcounter-exhausted marker、persist済みinternal-invariant fenceです。各markerを1 referenceとして同じpriorityへ数え、valid reconcile/authoritative recoveryでmarkerをclearするFULL commitが同じreferenceをclearします。Storage/Bearer/entropy/provider/clockのRuntime-instance-local causeはrestartで盲目的にcopyせず、new Port/provider observationで再評価します。Recovery完了時に未解決Storage fenceが残る場合はcreateを成功させず対応API error、成功createでは残存durable markerだけをStage 9 healthへprojectします。Metrics counterはnew epochでzeroでもhealth projectionはDEGRADEDになり得ます。

## 12. Public function signature

```c
ninlil_status_t ninlil_runtime_create(
    const ninlil_runtime_config_t *config,
    const ninlil_platform_ops_t *platform,
    ninlil_runtime_t **out_runtime);

ninlil_status_t ninlil_runtime_destroy(ninlil_runtime_t *runtime);

ninlil_status_t ninlil_service_register(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_service_t **out_service);

ninlil_status_t ninlil_submit(
    ninlil_service_t *service,
    const ninlil_submission_t *submission,
    ninlil_submission_result_t *out_result);

ninlil_status_t ninlil_offer_accept(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *offer_id,
    ninlil_submission_result_t *out_result);

ninlil_status_t ninlil_cancel_request(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_cancel_result_t *out_result);

ninlil_status_t ninlil_event_resume(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    ninlil_event_resume_result_t *out_result);

ninlil_status_t ninlil_event_discard(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    ninlil_event_discard_result_t *out_result);

ninlil_status_t ninlil_transaction_query(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *inout_snapshot);

ninlil_status_t ninlil_transaction_list(
    ninlil_runtime_t *runtime,
    const ninlil_query_t *query,
    ninlil_transaction_page_t *inout_page);

ninlil_status_t ninlil_delivery_complete(
    ninlil_runtime_t *runtime,
    const ninlil_delivery_token_t *token,
    const ninlil_application_result_t *result);

ninlil_status_t ninlil_runtime_step(
    ninlil_runtime_t *runtime,
    const ninlil_step_budget_t *budget,
    ninlil_step_result_t *out_result);

ninlil_status_t ninlil_capacity_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_capacity_snapshot_t *inout_snapshot);

ninlil_status_t ninlil_metrics_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_metrics_snapshot_t *out_snapshot);

#ifdef __cplusplus
}
#endif
```

## 13. Functionごとのownership、thread、出力

`runtime_create`以外のpublic APIは、required outer pointer/live handleとouter ABI headerを先に検証します。この段階のINVALID_ARGUMENT/ABI_MISMATCHではExecution Port call 0です。Valid live Runtimeへ到達したcallは`execution.current_context_id(user)`をexactly 1回呼び、0なら`NINLIL_E_DEGRADED`、captured ownerと不一致なら`NINLIL_E_WRONG_THREAD`です。Owner一致後、callback/re-entryを許さないfunctionは`NINLIL_E_REENTRANT`、許すquery/list/capacity/metricsはread-only pathへ進みます。その後だけnested input/semantic validationを行います。したがってprecedenceはouter invalid/ABI → context zero → wrong thread → re-entry → nested/semanticです。Execution call traceをcache、省略、複数pollしません。

| Function | Thread/re-entry | Input ownership | Success output | Error output |
| --- | --- | --- | --- | --- |
| runtime_create | caller contextをowner化。callback外 | config/vtableとnamespace source bufferはcall中borrowed。namespaceはStorage open前にdeep-copy。Port userはdestroyまで有効 | `*out_runtime` non-NULL | call開始時にNULL化し、常にNULL |
| runtime_destroy | owner、callback外 | validation成功後DESTROYING fenceからruntimeをconsume | active token group recovery-fence後、全handle/service invalidate | NULL/WRONG_THREAD/REENTRANTはconsumeしない。DESTROYING後はcleanup statusにかかわらずconsume |
| service_register | owner、callback外 | descriptor/viewとcallbacks structはcall中borrowed。descriptor文字列、callback function/user pointer値を成功前にcopy。non-NULL user pointee/codeはdestroyまでcaller管理 | service non-NULL | out serviceはNULL |
| submit | owner、callback外 | submission全pointerはcall中borrowed | result kindと必要ID/digest | API error時、header以外をzero、kind INVALID |
| offer_accept | owner、callback外 | borrowed | M1aではなし | 常にUNSUPPORTED、result INVALID |
| cancel_request | CONTROLLER owner、callback外 | borrowed | cancel kind | API error時kind 0、他field zero |
| event_resume | ENDPOINT owner、callback外 | metadataはcall中borrowed | persisted operation kind/cycle/revision | API error時kind INVALID、他zero |
| event_discard | ENDPOINT owner、callback外 | metadataはcall中borrowed | audit commit済みkind/revision | API error時kind INVALID、spool_released 0 |
| transaction_query | owner。callback中可 | target buffer caller-owned | scalar+全target | BUFFER_TOO_SMALL時target_countだけrequired値、target array未変更。他errorはheader/buffer info以外zero |
| transaction_list | owner。callback中可 | item buffer caller-owned | capacity内のascending partial page + cursor/has_more | normal paginationでBUFFER_TOO_SMALLなし。API errorはitems未変更、page header/pointer/capacity以外zero |
| delivery_complete | owner、callback外 | tokenはcopyable value、result/evidenceはcall中borrowed | result cache+token invalidation commit済み | 7.2 ordered tableのexact status/token rule。COMMIT_UNKNOWN/fenced中はrecoveryまで再call不可 |
| runtime_step | owner、callback外 | budget borrowed | bounded work結果 | error時処理済みcounterは保持しhealth/reason設定 |
| capacity_snapshot | owner。callback中可 | entries caller-owned | 全entry | BUFFER_TOO_SMALL時required countのみ |
| metrics_snapshot | owner。callback中可 | out caller-owned | snapshot | error時header以外zero |

Runtime destroy consume/lifecycle:

1. `runtime == NULL`は`NINLIL_E_INVALID_ARGUMENT`、wrong ownerは`NINLIL_E_WRONG_THREAD`、callback/re-entry中は`NINLIL_E_REENTRANT`です。このprecondition phaseではRuntime/Service/Port stateを変えず、valid handleをconsumeしません。
2. Validation成功後、Runtimeをin-memory `DESTROYING`へ不可逆にfenceします。このpoint以後は戻りstatusにかかわらずruntime/service/token handleをconsumeし、callback、Bearer send、positive Receipt/Disposition、public queryを追加実行しません。
3. Active tokenが1件以上あれば、`context_id` unsigned-byte lexicographic、次にgeneration昇順で全件を列挙し、各 token を **`token_state=EXPIRED`**、Delivery `RECOVERY_REQUIRED`、E_REC **`OUTCOME_UNKNOWN`**（effect `POSSIBLE`、completed zero）、active slot release へ **1つのStorage transaction / 1回のFULL commit**（operation kind **19**）で staging します。`runtime.before_destroy_recovery_commit` / `runtime.after_destroy_recovery_commit`はgroup全体に各最大1回です。個別token commitやpartial group visibilityを許しません。Active token 0ならStorage write/hook 0です。`APPLICATION_COMPLETION_TIMEOUT` や `CLOCK_UNCERTAIN` を destroy path の RESULT reason に使いません。
4. Group commit OKまたはfailure観測後、`bearer.close` → live transaction/iterator 0を確認して`storage.close` → service/table/namespace/runtime allocationをreverse orderでexactly once freeします。Port `user`はfreeしません。Close/deallocateはprimary statusを上書きしません。
5. No-active-tokenかgroup OKなら`NINLIL_OK`です。`BUSY`=`NINLIL_E_WOULD_BLOCK`、`NO_SPACE`=`NINLIL_E_CAPACITY_EXHAUSTED`、definite `IO_ERROR`/commit failure=`NINLIL_E_STORAGE`、`CORRUPT`/schema invariant=`NINLIL_E_STORAGE_CORRUPT`、`COMMIT_UNKNOWN`=`NINLIL_E_STORAGE_COMMIT_UNKNOWN`です。いずれもstep 2後なのでhandleはinvalidです。

Definite group failureではatomic Storage contractによりtoken mutation 0、COMMIT_UNKNOWNではall-or-none unknownです。どちらでもjournal/DELIVERY_STARTEDを削除せずStorage closeし、次のruntime_create recoveryがprevious process instanceの全active markerをcallback 0で`RECOVERY_REQUIRED`へ収束させます。旧processからcopyされたtokenは次createでactiveへ戻しません。Pending non-token transaction/outboxはjournalへ残し、destroy failureを理由にno-effect/terminalと推測しません。

追加規則:

- Public functionのruntime/service handle、required input struct、required ID、output pointerはすべてnon-NULLです。NULLはsemantic reducerへ入る前に`NINLIL_E_INVALID_ARGUMENT`です。`service_register`のcallbacks struct自体はrequiredで、function pointerだけが7.2の条件に従いNULL可です。
- Caller-owned arrayはcapacity 0ならpointer NULL、capacity > 0ならnon-NULLです。Query targets、list items、capacity entriesは提供した各要素のABI headerもcallerが初期化します。Bad element headerは`NINLIL_E_ABI_MISMATCH`でarray全体を変更せず、size/page semanticsは各functionの個別規則に従います。
- Output structはcall前にvalid ABI header、nested caller buffer pointer/capacityだけを設定し、他をzeroにします。API error時にlibrary-owned view、partial array、stale tokenを返しません。
- 構造/null/header validationはunsupported operation判定より先です。たとえばNULL offer IDは`INVALID_ARGUMENT`、well-formed `offer_accept`は`UNSUPPORTED`です。
- `ninlil_delivery_token_t`のidentity/generation/expiryはcallback前にFULL commitされます。ApplicationはDEFER時にstruct値をcopyします。pointerやRuntime内部objectのownershipは受け取りません。
- `delivery_complete`を同じtokenへ2回呼ぶと、invalid token retention中は`NINLIL_E_INVALID_STATE`、retention後は`NINLIL_E_NOT_FOUND`です。
- Callback内から`delivery_complete`を呼ぶと`NINLIL_E_REENTRANT`です。同期完了はcallbackのout resultを使用します。
- Runtime destroyはactive tokenをcompletion可能なまま持ち越しません。durable deliveryを`RECOVERY_REQUIRED`へ収束させ、non-terminal transactionをstorageへ残し、次createでrecoveryします。
- Reducerの「同じlogical timestamp」priorityは、比較対象inputがすでにRuntimeのdurable ingressへaccept/commit済みの場合だけ適用します。同期`cancel_request`、`event_resume`、`event_discard`はBearerを暗黙poll/drainせず、呼出し前にdurable ingress済みのinputの後へmanagement inputを追加します。
- Callerがprovider queue内のdue Receipt等をmanagementより先にしたい場合、明示`runtime_step`でdrainしてからmanagement APIを呼びます。まだBearer/provider queueだけにあるReceiptはbarrier対象でなく、discard/cancel commit後に届けばlate evidenceです。terminal Outcomeを反転せず、hidden blocking barrierを作りません。

## 14. M1a unsupported behavior

| Request | Result |
| --- | --- |
| named reserved role `CELL_AGENT_RESERVED` | runtime_create = `NINLIL_E_UNSUPPORTED` |
| role SIMULATOR | enum自体なし。外部harnessを使用 |
| named reserved environment `LAB_RESERVED` / `FIELD_RESERVED` / `PRODUCTION_RESERVED` | runtime_create = `NINLIL_E_UNSUPPORTED` |
| named reserved family `LATEST_STATE_RESERVED` / `MEASUREMENT_RESERVED` / `TRANSFER_RESERVED` / `CONFIG_RESERVED` / `NETWORK_CONTROL_RESERVED` | service_register = `NINLIL_E_UNSUPPORTED` |
| role/environment/family/direction/authority/apply/custody等のregistry外numeric enum | 対応API = `NINLIL_E_INVALID_ARGUMENT`。named reservedへ丸めない |
| EventFact/Command descriptorのwrong direction・authority・apply contract | service_register = `NINLIL_E_UNSUPPORTED`、service NULL |
| role × family matrixとcallback shape不一致 | service_register = `NINLIL_E_INVALID_ARGUMENT`、service NULL |
| Receiver service handleからsubmit | `NINLIL_OK` + submission REJECTED / `UNSUPPORTED_DIRECTION` / `RETRY_MODIFIED` / delay 0 |
| selector submission | ABI 0.1では表現不能。larger `struct_size`のunknown tailはignoredなので検出を主張しない。新ABI/capabilityが必要 |
| caller scheduled/not-before要求 | ABI 0.1では表現不能。unknown tailから推測しない。M1a reducerは`ADMITTED_SCHEDULED`を生成せず、新ABI/capabilityが必要 |
| counter-offer | Runtimeは生成しない。offer_accept = `NINLIL_E_UNSUPPORTED` |
| atomic application storage participant | service_register = `NINLIL_E_UNSUPPORTED` |
| supersede/replace | ABI 0.1にfield/APIなし。unknown tailはignoredで検出を主張せず、新ABI/capabilityが必要 |
| fragment/attachment | ABI 0.1にfield/APIなし。unknown tailはignoredで検出を主張せず、新ABI/capabilityが必要 |
| 0または2以上のtargets | `NINLIL_OK` + submission REJECTED / `TARGET_COUNT_UNSUPPORTED` |
| Endpointからcancel、またはControllerのexisting EventFact cancel | `NINLIL_E_UNSUPPORTED`。EventFact diagnostic reasonは`EVENT_FACT_IMMUTABLE`、API result zero、spool不変 |
| Controllerからevent_resume/discard | `NINLIL_E_UNSUPPORTED`、result INVALID/zero |
| otherwise well-formed query/cancel/event managementのunknown・retention-cleaned transaction ID | `NINLIL_E_NOT_FOUND`、各error-output規則どおりzero |
| EventFact finite deadline/non-zero grace | `NINLIL_OK` + submission REJECTED / `EVENTFACT_DEADLINE_UNSUPPORTED` |
| Command no deadline/範囲外deadline | `NINLIL_OK` + submission REJECTED / `DEADLINE_INVALID` |

## 15. Canonical Submission Digest v1

[14-foundation-ports-and-simulator.md](14-foundation-ports-and-simulator.md)の「Canonical Submission Encoding v1」とgolden vectorsだけがbyte encoding、integer endian、field tag/order、vector digestの正本です。本章は別のTLVやgolden digestを定義しません。実装はC struct memory、padding、pointer、host endianをhashしてはなりません。

ABIから14章canonical fieldへの入力mappingは次で固定します。

| Canonical field | ABI source |
| --- | --- |
| namespace、service ID | registered `ninlil_service_descriptor_t.namespace_id/service_id` |
| descriptor revision/digest | registered descriptorの同名field |
| source application instance | registered descriptorの`local_application_instance_id` |
| family | descriptor `family`。public valueはEventFact=1、DesiredStateCommand=2 |
| schema identity/version | descriptor `schema_id/schema_major`とSubmission `schema_minor` |
| concrete target roster | Submission `target_count`と各`ninlil_concrete_target_t`全field。M1a admitted countはexactly 1 |
| effect deadline、evidence grace、required evidence | Submission同名field |
| family metadata | DesiredStateは`generation`、EventFactは`event_id` |
| content digest、payload length | Submission `content_digest`と`payload.length` |

Idempotency keyは`source application instance + namespace + service ID` scopeのlookup keyでありcanonical bytesへ含めません。source runtime/local identity、transaction/attempt ID、grant/provider identity・revision・expiry、permit、raw payload、apply contractのdirect valueも含めません。apply contractを含むservice contractはdescriptor digestでbindingします。caller scheduled/not-before fieldはM1a ABIに存在せず、canonicalへ追加しません。

0または2以上のtargetは`TARGET_COUNT_UNSUPPORTED`でrejectionし、M1a required golden vectorに2-target success/sortを置きません。2-target canonical fixtureはM1b以降のforward-only資料であり、M1a conformance claimに使用しません。

## 16. M1a Service fixture requirements

### DesiredStateCommand

- CONTROLLER senderは両callback NULLでsubmitし、ENDPOINT receiverは`on_delivery`を登録してreceiveします。Fixture apply contractは`IDEMPOTENT`なのでEndpoint `on_reconcile`はNULLです。Controller service handleへのinbound Application、Endpoint service handleからのsubmitは成功経路にしません。
- payloadは`desired_state u8 + generation u64 LE`です。
- generationはSubmission fieldとpayload内で一致必須です。
- required evidenceはAPPLIEDです。
- effect deadline 5000ms、grace 1000msです。
- Endpoint applicationはabsolute assignmentを行い、再callbackされても同じdesired stateになります。
- callback完了後cache前crashでは同一transactionを再applyできます。callback invocation回数とsemantic state change回数を別metricにします。

### EventFact

- ENDPOINT senderは両callback NULLでorigin admissionし、CONTROLLER receiverは`on_delivery`と`on_reconcile`を登録してreceiveします。Controller service handleからのsubmit、Endpoint service handleへのinbound Applicationは成功経路にしません。
- payloadは`event_kind u16 LE + observed_sequence u64 LE`です。
- required evidenceはDURABLY_RECORDEDです。
- deadlineは`NINLIL_NO_DEADLINE`です。
- Controller applicationはevent IDをunique keyにし、duplicate callbackでbusiness recordを増やしません。
- Controller business commit完了後だけDURABLY_RECORDEDを返します。
- retry cycle枯渇後もorigin spoolから消しません。
- explicit discardだけがReceipt未到達EventFactをspoolから除去できます。

## 17. Named fault hook registry

M1a TEST buildのfault hook名は次のclosed registryだけです。12章が正本で、08/14章、fixture、scriptはexact stringを使用します。Unknown name、重複定義、prefix wildcardはscenario validation errorで、silent ignoreしません。

```text
# Runtime foundational durable boundaries
runtime.before_service_registry_commit
runtime.after_service_registry_commit
runtime.before_ingress_copy_commit
runtime.after_ingress_copy_commit
runtime.before_bearer_state_commit
runtime.after_bearer_state_commit
runtime.before_reverse_send_observation_commit
runtime.after_reverse_send_observation_commit
runtime.before_retention_basis_commit
runtime.after_retention_basis_commit
runtime.before_namespace_binding_commit
runtime.after_namespace_binding_commit
runtime.before_identity_rotation_commit
runtime.after_identity_rotation_commit

# Controller admission / ownership
controller.before_admission_begin
controller.after_transaction_put
controller.after_roster_put
controller.after_reservation_put
controller.after_idempotency_put
controller.after_outbox_put
controller.before_admission_commit
controller.after_admission_commit

# Endpoint EventFact origin admission
endpoint.before_event_admission_begin
endpoint.after_event_transaction_put
endpoint.after_event_key_mapping_put
endpoint.after_event_id_mapping_put
endpoint.after_event_grant_put
endpoint.after_event_spool_put
endpoint.before_event_admission_commit
endpoint.after_event_admission_commit

# Application/cancel attempt preparation and send
controller.before_attempt_prepare_commit
controller.after_attempt_prepare_commit
controller.after_bearer_send
controller.before_application_send_observation_commit
controller.after_application_send_observation_commit
endpoint.before_attempt_prepare_commit
endpoint.after_attempt_prepare_commit
endpoint.after_bearer_send
endpoint.before_application_send_observation_commit
endpoint.after_application_send_observation_commit
controller.before_cancel_prepare_commit
controller.after_cancel_prepare_commit
controller.before_cancel_send_gate_commit
controller.after_cancel_send_gate_commit
controller.after_cancel_bearer_send

# Receipt / Disposition / custody ingress and send
controller.before_receipt_commit
controller.after_receipt_commit
endpoint.before_receipt_commit
endpoint.after_receipt_commit
controller.before_receipt_send
endpoint.before_receipt_send
controller.before_disposition_commit
controller.after_disposition_commit
endpoint.before_disposition_commit
endpoint.after_disposition_commit
controller.before_custody_send
endpoint.before_custody_send

# Controller Command timeout / deadline terminal commits
controller.before_command_attempt_timeout_commit
controller.after_command_attempt_timeout_commit
controller.before_evidence_close_commit
controller.after_evidence_close_commit
controller.before_deadline_terminal_commit
controller.after_deadline_terminal_commit

# Delivery ingress, durable token, application callback, result
controller.before_delivery_ingress_commit
controller.after_delivery_ingress_commit
endpoint.before_delivery_ingress_commit
endpoint.after_delivery_ingress_commit
controller.before_delivery_started_commit
controller.after_delivery_started_commit
endpoint.before_delivery_started_commit
endpoint.after_delivery_started_commit
controller.before_delivery_start_counter_exhausted_commit
controller.after_delivery_start_counter_exhausted_commit
endpoint.before_delivery_start_counter_exhausted_commit
endpoint.after_delivery_start_counter_exhausted_commit
controller.before_application_callback
controller.after_application_effect
controller.after_application_callback
endpoint.before_application_callback
endpoint.after_application_effect
endpoint.after_application_callback
controller.before_callback_recovery_commit
controller.after_callback_recovery_commit
endpoint.before_callback_recovery_commit
endpoint.after_callback_recovery_commit
controller.before_result_cache_commit
controller.after_result_cache_commit
endpoint.before_result_cache_commit
endpoint.after_result_cache_commit
controller.before_token_timeout_commit
controller.after_token_timeout_commit
endpoint.before_token_timeout_commit
endpoint.after_token_timeout_commit

# Reconcile
controller.before_reconcile_callback
controller.after_reconcile_callback
controller.before_reconcile_commit
controller.after_reconcile_commit
endpoint.before_reconcile_callback
endpoint.after_reconcile_callback
endpoint.before_reconcile_commit
endpoint.after_reconcile_commit

# Remote cancel receive/result
endpoint.before_cancel_tombstone_commit
endpoint.after_cancel_tombstone_commit
endpoint.before_cancel_result_send
controller.before_cancel_result_commit
controller.after_cancel_result_commit

# Event retry, park, availability resume, release
endpoint.before_event_attempt_timeout_commit
endpoint.after_event_attempt_timeout_commit
endpoint.before_event_park_commit
endpoint.after_event_park_commit
endpoint.before_event_availability_resume_commit
endpoint.after_event_availability_resume_commit

# Explicit Event resume / discard
endpoint.before_event_resume_commit
endpoint.after_event_resume_commit
endpoint.before_event_discard_commit
endpoint.after_event_discard_payload_erase
endpoint.after_event_discard_commit

# Runtime cleanup / commit-unknown / recovery
runtime.after_commit_unknown_observed
runtime.before_destroy_recovery_commit
runtime.after_destroy_recovery_commit
runtime.before_storage_reopen
runtime.after_storage_reopen
runtime.before_recovery_scan
runtime.after_recovery_scan
runtime.before_recovery_item_commit
runtime.after_recovery_item_commit
runtime.before_terminal_cleanup_commit
runtime.after_terminal_cleanup_commit
runtime.before_result_cache_cleanup_commit
runtime.after_result_cache_cleanup_commit
runtime.before_token_tombstone_cleanup_commit
runtime.after_token_tombstone_cleanup_commit
runtime.before_capacity_epoch_commit
runtime.after_capacity_epoch_commit
```

Placement contract:

| Transition boundary | Exact hook pair | No-hook cases |
| --- | --- | --- |
| current DesiredStateCommand `ATTEMPT_RECEIPT_TIMEOUT` state/effect commit | `controller.before_command_attempt_timeout_commit` / `controller.after_command_attempt_timeout_commit` | stale timeout、先にreduce済みReceipt/Disposition、EventFact timeout |
| DesiredStateCommand `EVIDENCE_CLOSE` required未達 terminal commit | `controller.before_evidence_close_commit` / `controller.after_evidence_close_commit` | EventFact、required evidenceが先にterminalized済み |
| admitted Commandのfirst-dispatch前deadline guard terminal commit | `controller.before_deadline_terminal_commit` / `controller.after_deadline_terminal_commit` | pre-admission rejection、既にApplication attempt prepared済みの通常effect deadline |
| `CALLBACK_FATAL`、unknown callback action、invalid COMPLETE resultのtoken invalidation + `RECOVERY_REQUIRED` commit（kind11；FATAL=`APPLICATION_FAILED`+`RECOVERY_REQUIRED_TOMBSTONE`、contract=`CALLBACK_CONTRACT`+同tombstone） | Receiver roleに応じた`controller.before_callback_recovery_commit` / `controller.after_callback_recovery_commit`または`endpoint.before_callback_recovery_commit` / `endpoint.after_callback_recovery_commit` | callback前commit failure；reconcile result は `*_reconcile_commit`（unknown/invalid KNOWN は RESULT E_REC を `CALLBACK_CONTRACT` へ置換） |
| DELIVERY_START success FULL（kind9 phase1：post `N`+ACTIVE） | role `*_delivery_started_commit` | counter exhausted path |
| DELIVERY_START `N+1` 不能 FULL（kind9 phase2：`N=MAX`+tombstone維持+`COUNTER_EXHAUSTED`、callback 0） | role `*_delivery_start_counter_exhausted_commit` | **`*_delivery_started_commit` への alias 禁止** |
| accepted application result / delivery_complete FULL（kind10 phase1：CONSUMED+terminal） | role `*_result_cache_commit` | timeout path |
| active token timeout FULL（kind10 phase2：EXPIRED+`APPLICATION_COMPLETION_TIMEOUT`） | role `*_token_timeout_commit` | complete success path、stale tombstone complete |
| destroy / Stage recovery が ACTIVE token を EXPIRED+`OUTCOME_UNKNOWN` へ（kind19/21；clock は health CLOCK_FENCE のみ、RESULT に `CLOCK_UNCERTAIN` を書かない） | destroy=`runtime.*_destroy_recovery_commit`、clock/create item=`runtime.*_recovery_item_commit` | COMMIT_UNKNOWN 中の推測 mutation |
| remote cancel send gateのpre-send close / definite-WOULD_BLOCK reopen commit | `controller.before_cancel_send_gate_commit` / `controller.after_cancel_send_gate_commit` | new cancel attempt preparation（`controller.before_cancel_prepare_commit` / `controller.after_cancel_prepare_commit`）、Bearer invocation return（`controller.after_cancel_bearer_send`） |
| first durable service semantic registry commit | `runtime.before_service_registry_commit` / `runtime.after_service_registry_commit` | recreate attach、same-Runtime exact reregister |
| provider-owned messageのINGRESS copy + ordered sequence commit | `runtime.before_ingress_copy_commit` / `runtime.after_ingress_copy_commit` | semantic reducer Receipt/Delivery commit、invalid pre-copy shape |
| Bearer state new epoch/availability observation commit | `runtime.before_bearer_state_commit` / `runtime.after_bearer_state_commit` | exact same epoch/flag、old epoch、state temporary/error、same epoch/different flag、budget不足。ordered-input sequence / scheduler ownerは消費しない |
| ordinary Application-send micro-operationのfinal observation + scheduler cursor commit（TxGate TEMP/DENIED/contract no-send、またはBearer return。Eventが同commitでPARKEDへ進む場合を含む） | Sender roleに応じた`controller.before_application_send_observation_commit` / `after`または`endpoint.before_application_send_observation_commit` / `after` | TxGate acquire自体のtemporary Port failureでsemantic commit 0、reverse/cancel send、Event park pair |
| cached reverse replyのpost-send observation state commit | `runtime.before_reverse_send_observation_commit` / `runtime.after_reverse_send_observation_commit` | cancel REQUEST send gate、Bearer未invoke、duplicate inboundによるPENDING化前 |
| retention basis pending設定/rebase/overflow marker commit | `runtime.before_retention_basis_commit` / `runtime.after_retention_basis_commit` | actual terminal/result commitの既存specific pair、retention cleanup pair |
| empty namespace binding/capacity/4 counter初期化 group | `runtime.before_namespace_binding_commit` / `runtime.after_namespace_binding_commit` | exact reopen、identity-only rotation、partial existing namespace |
| current installation/site identity forward rotation group | `runtime.before_identity_rotation_commit` / `runtime.after_identity_rotation_commit` | exact same identity、stale/conflict/device mismatch、initial namespace binding |

この表のtransitionはgeneric `runtime.before_recovery_item_commit`へaliasしません。Crash/restart recoveryが同じ未commit transitionを再実行するときも同じspecific pairを通り、before hookでcrashしたcommitにはafter hookが発生しません。

1つのFULL commitに複数の意味が含まれてもnamed commit pairはexactly 1組です。次のoverlap tableを上から適用し、secondary pair occurrenceは0です。

| Atomic transition | Primary pair | Secondary occurrence 0 |
| --- | --- | --- |
| valid Receipt commitがCommand/Event terminal、evidence、Event payload releaseを同時に行う | receiver roleの`*_receipt_commit` | event release専用pairはregistryに存在しない |
| Event current 8th attempt timeoutがsummary compaction + PARKEDを同時に行う | `endpoint.*_event_attempt_timeout_commit` | event park。summary専用pairはregistryに存在しない |
| Event non-timeout TxGate/Bearer resultがsend observationと同時にPARKEDへ進む | `endpoint.*_application_send_observation_commit` | event park / attempt timeout |
| Eventのdurable Dispositionまたはsend外reducer inputがPARKEDへ進む | `endpoint.*_event_park_commit` | application send observation / attempt timeout |
| Availability consumeがsummary compaction + new cycle + READYを同時に行う | `endpoint.*_event_availability_resume_commit` | event park/resume |
| Explicit resumeがsummary compaction + new cycle + READYを同時に行う | `endpoint.*_event_resume_commit` | availability/park |
| Explicit discardがterminal + payload erase + auditを同時に行う | `endpoint.*_event_discard_commit`（payload write直後の`after_event_discard_payload_erase`はpairでないwrite hookとして併用） | receipt/cleanup |
| Application send resultがstate/timer/health/cursorを同時に更新 | role-specific application-send-observation pair | generic recovery/reverse pair |
| Terminal retention cleanupがattempt index/evidence/resource/capacity MAX markerを同時release | `runtime.*_terminal_cleanup_commit` | capacity pair。ただしcapacity epochだけを独立変更するcommitはcapacity pair |

- `before_*_commit`は全staged write完了後、Storage `commit(FULL)`呼出し直前です。`after_*_commit`はcommit `OK`観測後、in-memory projection更新、public success、payload release、send/callback等の次side effect前です。COMMIT_UNKNOWN/definite failureでは対応するafter hookへ到達しません。
- `after_*_put` / `after_event_discard_payload_erase`は同じactive storage transaction内の該当write成功直後で、commit前です。Hook crash後は未commit writeが可視化されないStorage contractを検査します。
- `before_*_callback`はdurable token/recovery marker commit後、applicationへ入る直前、`after_*_callback`はreturn action/resultをCoreが読む直後、result state commit前です。`after_application_effect`はconformance fixture applicationがbusiness effect commit直後にdispatchするtest hookです。
- `after_*_send`はBearer `send` return直後で、send result ObservationのCore commit前です。`before_*_send`はrequired result/custody commit後、TxPermit acquire前です。
- Hook occurrenceは`runtime_id + exact hook name`ごとに1からchecked countします。Contextは存在するruntime、operation、transaction、attempt、delivery token ID/generationをimmutable valueで渡します。Hook callbackはCoreへ再入せず、crashまたは次Port failureだけをscheduleします。
- Production buildではdispatchをcompile outできますが、hook有無でwrite/commit/callback/send順を変えません。Fault hook API自体はRuntime roleでもpublic application APIでもありません。

## 18. Conformance minimum

M1a public ABI conformanceは最低限次を検査します。

- C11/C++17 consumer compile/link
- 全enum値と`offsetof`/`sizeof`のgenerated ABI manifest
- small/future `struct_size`
- nullability表の全組合せ
- API error時out field
- named reserved enum=`UNSUPPORTED`とregistry外numeric enum=`INVALID_ARGUMENT`の全public input、`E_CALLBACK`/`E_INTERNAL`/`HEALTH_FATAL`生成0
- reason generated-zero exact 9-symbol YAML set、provider temporary/permanent domain、GRANT_PROVIDER_UNAVAILABLE health guidance OPERATOR_ACTION
- wrong owner execution context、callback re-entry、copy tokenのdouble/late completion
- allocator failureの全public allocation point。特にstorage namespace copy失敗はStorage open 0、runtime NULL、allocation leak 0
- storage namespace length 0/1/255/256、null mismatch、embedded NUL/non-UTF-8、caller buffer mutation/free後のcopy independence、Storage openへexact length/bytes、failure/destroy時exactly-once free
- storage status mapping、commit unknown、iterator order
- mut_bytes capacity/null/input length、get/iter success/too-small/not-found/error data immutability、iter pair atomicity/position
- Bearer deep-copy/release lifetime、permit必須、epoch増加
- role × family 4-row service registration/callback matrix、receiver submitのexact direction rejection、wrong-role cancel/event management、unknown/retention-expired query/cancel/event management
- exact service再登録でsame handle pointer・allocation/SERVICE capacity/callback mutation 0、valid mismatchでCONFLICT
- runtime resource role/range/conditional-zero/cross-field/retention全boundaryとEndpoint event capability 0/0 registration rejection
- callback struct address非保持、function/user value copy、NULL user、non-NULL user/code lifetime、Runtime初期化済みout result header/zero、semantic field only、COMPLETE/KNOWN_RESULT evidence synchronous deep-copy、ignored actionでevidence dereference 0
- supported evidence maskの全non-empty known-bit subset、NONE/reserved bit rejection、advertiseだけでReceipt生成0
- selector/scheduled field不在、reserved reason/result生成0、counter-offer/atomic participant unsupported
- idempotency scopeとcanonical digest vector
- Submission result全kind field matrix、conflict existing ID/digest、rejected digest zero、nested assurance header/zero
- Command idempotent crash/reconcile
- EventFact no deadline、PARKED_RETRY、自動/manual resume
- discard audit commit前spool release 0
- remote cancel prepared attempt/entropy 1件、pre-send durable close、WOULD_BLOCK observation commit後だけsame-attempt reinvoke、accepted/unknown/crash/restart後request reinvoke 0
- runtime_create 9-stage first-failure precedence、全Storage/Bearer/clock/entropy mapping、combined fault、reverse cleanup/leak 0
- runtime_destroy precondition non-consume、DESTROYING consume point、0/1/複数active token single atomic group、definite/unknown commit後close/free/recreate recovery
- callback前DELIVERY_STARTED commit、deferred token timeout、retention中late complete INVALID_STATE/retention後NOT_FOUND、active slot再利用
- transaction query target buffer不足とtransaction list page-size semanticsの分離
- transaction list page capacity 2で3 matching rowをOK partial page + has_more、capacity 0のmatching/non-matching、bad item header atomic error
- capacity entry全provided header、bad header ABI_MISMATCH precedence、capacity 0/10/11/12と余剰element不変
- delivery_complete ordered validation全row、malformed result/evidence、unknown/known-invalid token、clock uncertain/epoch mismatch/expiry超過、各Storage mapping、definite failure/COMMIT_UNKNOWN後token rule
- step budget各unit/increment point、callback/send worst-case preflight、budget 0/境界、terminalized/parked重複0
- metrics全counter increment/reset/saturation、health active-cause add/clear/current-priority、OK/NONE invariant
- EVENT_SPOOL_BYTES exact payload+2560 portable formula、used/reserved slot移行、attempt/summary physical overhead除外
- capacity/metrics counterの意味分離

M1aの完了は、このABIとobservable behaviorを満たすことです。実radio、Attachment、production credential、法令profileの完成を意味しません。
