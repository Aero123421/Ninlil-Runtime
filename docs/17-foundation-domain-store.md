# 17. Foundation Domain Store v1

状態: **Normative / pre-alpha storage format**
対象: Foundation M1a private Runtime Store family 5 / 6

本章は[12章](12-foundation-abi.md)のPrivate Runtime Store v1を拡張し、Runtime create Stage 5がdomain recovery、counter/capacity相互検査、durable health再構成を完了するための正本を定めます。Public C ABI、radio wire、Bearer message encodingではありません。

## 1. Scopeとpublish gate

本章が固定するのは、domain record catalog、key/value形式、atomic witness、retention、resource contribution、read-only recovery scanです。Reducer writer、SQLite、embedded KV、public `runtime_create()` bodyは後続実装です。

Runtimeは次の全条件を証明するまでpublic handleをpublishしてはなりません。

1. family 1〜4 bootstrap/profile検査完了
2. family 5 / 6全row scan完了
3. 15 WITNESS_HEAD_INDEX baseline/witnessed exact + CLOCK_BASELINE present、primary/index/backlink、witness、4 counter、11 capacity検査完了
4. unresolved old/new group 0
5. identity exactまたはforward rotation commit OK
6. CLOCK_BASELINE TRUSTEDかつcurrent Stage 7 sample commit OK
7. Storage priority 1/2 reference 0
8. transaction/iterator 0、exclusive Storage handle 1

Bootstrap直後のphysical empty domainはfamily 5/6 row 0で、metadata初期化前のrecovery transientとしてだけvalidです。Public publish可能なsemantic empty domainはexact 15 BASELINE WITNESS_HEAD_INDEX + 1 TRUSTED CLOCK_BASELINEとbusiness/health/witness row 0です。Stage 5直後のUNINITIALIZED clockはStage 7前だけvalidです。0-rowをpublish可能emptyと推測せず、full scan→16-record metadata初期化→fresh scanを必須とします。

## 2. Bounded format constants

| Name | Exact value |
| --- | ---: |
| `DOMAIN_FORMAT_VERSION` | 1 |
| `DOMAIN_RECORD_VERSION` | 1 |
| `PRIVATE_RECORD_MAX_BYTES` | 4096 |
| `PRIVATE_BODY_MAX_BYTES` | 3984 |
| `BLOB_CHUNK_DATA_MAX_BYTES` | 3072 |
| `WITNESS_MEMBER_MAX` | 256 |
| `WITNESS_ENTRIES_PER_CHUNK` | 8 |
| `WITNESS_CHUNK_MAX` | 32 |
| raw idempotency key max | 64 |
| audit metadata max | 128 |
| evidence bytes max | 128 |

`PRIVATE_RECORD_MAX_BYTES`はNinlil private namespaceのcurrent/future全root versionが生成・受理できるsingle value上限です。Storage ABIの65,536-byte上限とは別で、future formatもchunkingを使います。4097 bytes以上、または255-byte key/4096-byte value scratchへの`iter_next`がrequired key>255またはvalue>4096で`BUFFER_TOO_SMALL`を返すrowは、key/value bytesを推測せず`NINLIL_E_STORAGE_CORRUPT`です。ESP32 task stackへscratchを置かず、Runtime-owned workspaceを使います。

Logical payloadは1 recordへ詰めず、3072-byte以下のchunkに分割します。Chunk countは`ceil(total_length / 3072)`、zero-length blobだけcount 0です。非末尾chunkはexact 3072 bytes、末尾は1..3072 bytesです。

## 3. Integer、digest、reusable encoding

全integerはunsigned big-endianです。Booleanはu32 exact 0/1です。ABI header、reserved、pointer、padding、host endianを保存しません。

- `ID128`: exact 16 bytes
- `DIGEST256`: exact 32 bytes。SHA-256を指定したfieldだけで使用
- `TEXT_ID`: `length:u8 + bytes[length]`、length 1..63、unused bytesなし
- `RAW16`: `length:u16 + bytes[length]`
- `LOCAL_IDENTITY`: `flags:u32 + device[16] + installation[16] + site[16] + binding_epoch:u64 + membership_epoch:u64`
- `PARTY`: `runtime_id[16] + application_instance_id[16] + LOCAL_IDENTITY`
- `TARGET`: `flags:u32 + target_runtime[16] + target_application[16] + device[16] + installation[16] + site[16] + binding_epoch:u64 + membership_epoch:u64`
- `SERVICE_IDENTITY`: `TEXT_ID(namespace) + TEXT_ID(service) + TEXT_ID(schema) + descriptor_revision:u64 + descriptor_digest[32] + schema_major:u16 + schema_minor:u16 + family:u32`
- `RESOURCE_VECTOR`: kind 1..11の宣言順に`used:u64 + reserved:u64`を11回

Presence、zero ID、epoch、known enumの規則は12章public ABIと同じです。Hash keyを使うrecordはbodyへexact raw identityを重複保存し、hash一致だけで同一性を決めません。

## 4. Envelopeとdomain common header

Family 5/6 valueは12章6.2の`NLR1` envelopeを使います。`record_type=5`はhealth marker、`record_type=6`はdomain recordです。`record_version=1`、total `12 + payload_length + 4 <= 4096`です。

Family 5/6 payloadは次のexact common headerから始まります。

```text
domain_format       u16 = 1
subtype             u8, key subtypeとexact一致
flags               u8, subtypeごとのknown bitだけ
record_revision     u64, 1..UINT64_MAX
primary_id          16 bytes
head_witness_digest 32 bytes
primary_value_digest 32 bytes
body_length         u32
body                exact body_length bytes
```

Common headerは96 bytesです。`record_revision`は1始まり、replacement時にcurrent<UINT64_MAXならchecked +1します。TRANSACTION_STATE、EVIDENCE_CELL、EVENT_SPOOL、RESULT_CACHE、RETRY_SUMMARYは12/13章がMAX後も許すlate/duplicate/saturating updateだけcurrent=MAXを維持でき、他subtypeのMAX replacementはCOUNTER_EXHAUSTED/fail closedです。Value changeの一意性はrevisionだけでなくcomplete value digestとwitness headで判定します。TRANSACTION_STATEではpublic `record_revision`と同値です。Family 5/6 semantic business recordはmember 1件だけのmutationでもwitnessを使い、current revisionの`head_witness_digest`はnon-zeroです。Zero headを許すのはfamily 5 INTERNAL_INVARIANT、CLOCK_BASELINE、WITNESS_HEADER/CHUNK、BASELINE WITNESS_HEAD_INDEXだけです。WITNESSED HEAD_INDEXはnon-zeroです。BEARER_STATEを含む他family 6 recordのzero headはcorruptです。Family 3/4 memberはcommon headerを持たないためHEAD_INDEXとmanifest value digestで照合します。`primary_value_digest`はprimary recordではzero、secondary recordでは同じsnapshotにあるcomplete primary encoded valueのSHA-256です。Body trailing byteは禁止です。

Common `flags`はBLOBだけbit 0=manifest / bit 1=chunkのどちらかexact 1つを設定し、他subtypeは0です。Unknown bit、両bit、body variantとの不一致はcorruptです。

`primary_id`はprimary recordでは自分、secondaryでは参照primaryのidentityを16 bytesへ写したhintです。ID128はそのID、u64/singletonはleft zero-padしたbig-endian identity、digest keyはdigest先頭16 bytesです。これはlookup補助であり、最終同一性はbody内raw identityから再構成したcomplete primary keyと`primary_value_digest`で判定します。

## 5. Key grammar

Rootは12章と同じexact 8 bytes `4e494e4c494c0001`です。

```text
root[8] | family:u8 | subtype:u8 | key_format:u8=1 |
identity_kind:u8 | identity_length:u8 | identity[identity_length]
```

Key lengthは13..45 bytesです。Identity kindはclosedです。

| Kind | Value | Length |
| --- | ---: | ---: |
| singleton | 1 | 0 |
| ID128 | 2 | 16 |
| u64 | 3 | 8 |
| SHA-256 of exact raw identity | 4 | 32 |
| SHA-256 of typed composite identity | 5 | 32 |

Family 5は`family=05`、family 6は`family=06`です。Current keyspaceのunknown subtype/kind/lengthはcorruptです。Recognizable future rootは、key length 8..255、先頭7 bytesがexact `4e494e4c494c00`、8 byte目のunsigned versionが2..255、value length 16..4096、valueがcomplete `NLR1` envelope（magic、declared length、CRC32Cがvalid）であるrowだけです。Future rootの残りkey bytesとenvelope `record_type` / `record_version`は解釈しません。このpredicateを満たすrowが1件以上ありcurrent corruptionが0ならunsupported、prefixだけ一致するshort key、version 0、invalid/partial envelope、required key>255/value>4096はcorruptです。Current rootのenvelope `record_version>1`またはfamily 5/6 `domain_format>1`も、該当version fieldまで安全にdecodeできcurrent corruptionが0の場合だけunsupportedです。

### 5.1 Digestの正本

`VALUE_DIGEST(v)`はCRCを含むcomplete `NLR1` encoded value bytes全体の`SHA-256(v)`です。Fieldの一部、decoded body、host structのhashではありません。Key digestは次のexact preimageだけを使います。ASCII separatorは表記されたbyte列そのもので、NUL terminatorを含みません。`RAW16`はlength prefixを含むencoding、u16/u32/u64は本章のbig-endianです。

```text
COMPOSITE(subtype, components) =
  SHA-256(ASCII("NINLIL-DOMAIN-KEY-V1") || subtype:u8 || components)

KEY_DIGEST(complete_key) =
  SHA-256(ASCII("NINLIL-DOMAIN-ENCODED-KEY-V1") || complete_key_bytes)
```

Field名が`*_key_digest`、`primary_key_digest`、`manifest_key_digest`、`subject_primary_key_digest`で終わる場合は、identity kindに関係なくroot/family/subtype/key format/kind/length/identityを含むcomplete encoded keyの`KEY_DIGEST`です。Composite identityそのもの、key先頭16 bytes、value digestではありません。`witness_digest`だけはWITNESS_HEADER composite identityそのものです。

| Subtype / variant | Exact components |
| --- | --- |
| SERVICE `10` | `service_key_raw:RAW16` |
| SERVICE_QUOTA `11` | `service_key_raw:RAW16` |
| RESERVATION `23` | `owner_kind:u16 || owner_key_raw:RAW16` |
| IDEMPOTENCY_MAP `24` | `scope_raw:RAW16 || idempotency_key:RAW16` |
| EVENT_ID_MAP `25` | `scope_raw:RAW16 || event_id[16]` |
| BLOB manifest `30` | `u8=1 || blob_id_digest[32]` |
| BLOB chunk `30` | `u8=2 || blob_id_digest[32] || chunk_index:u32` |
| ATTEMPT `31` | `attempt_owner_kind:u16 || owner_key_raw:RAW16 || attempt_id[16]` |
| EVIDENCE_CELL `32` | `evidence_owner_kind:u16 || owner_key_raw:RAW16 || slot_index:u32` |
| CANCEL_STATE `33` | `cancel_owner_kind:u16 || owner_key_raw:RAW16` |
| DELIVERY `40` | `delivery_key_raw:RAW16` |
| RESULT_CACHE `41` | `delivery_key_raw:RAW16` |
| REVERSE_REPLY `42` | `reply_key_raw:RAW16` |
| RETRY_SUMMARY `51` | `transaction_id[16] || summary_kind:u16 || slot_index:u16` |
| MANAGEMENT_LEDGER `52` | `transaction_id[16] || operation_id[16]` |
| RETENTION_BASIS `61` | `subject_kind:u16 || subject_key_raw:RAW16` |
| CLEANUP_PLAN `63` | `subject_kind:u16 || subject_primary_key_digest[32]` |
| WITNESS_HEAD_INDEX `7d` | `member_key_digest[32]` |
| WITNESS_MANIFEST_CHUNK `7e` | `witness_digest[32] || chunk_index:u16` |
| WITNESS_HEADER `7f` | `operation_kind:u16 || operation_identity:RAW16` |

Reusable raw identityのcontentsもclosedです。

| Name | Exact contents（外側RAW16 lengthは含めない） |
| --- | --- |
| `service_key_raw` | `local_application_instance_id[16] || namespace:TEXT_ID || service:TEXT_ID || descriptor_revision:u64 || descriptor_digest[32]` |
| idempotency/event `scope_raw` | `source.application_instance_id[16] || service.namespace:TEXT_ID || service.service:TEXT_ID` |
| `delivery_key_raw` | `source.runtime_id[16] || source.application_instance_id[16] || transaction_id[16] || local_target.runtime_id[16] || local_target.application_instance_id[16]` |
| `reply_key_raw` | `delivery_key_raw:RAW16 || reply_kind:u32` |
| `subject_key_raw` | subject primaryのkey identity raw bytes。ID128=16 bytes、u64=8 bytes、composite=その元components encoding |

`target_digest = SHA-256(ASCII("NINLIL-DOMAIN-TARGET-V1") || TARGET)`です。`blob_id_digest = SHA-256(ASCII("NINLIL-DOMAIN-BLOB-ID-V1") || blob_owner_kind:u16 || owner_key_raw:RAW16 || blob_kind:u16 || content_digest[32] || total_length:u64)`です。これらのpreimageにABI header、pointer、padding、reserved byteを含めません。

同じdigestを別domainで再利用しません。`witness_digest`は上表のWITNESS_HEADER composite digestそのもので、header value digestではありません。Manifest digestは`SHA-256(ASCII("NINLIL-DOMAIN-MANIFEST-V1") || chunk_body_0 || ... || chunk_body_n)`です。Bodyが持つdigest-key identity componentは全てexact raw bytesを重複保存し、keyとの再計算一致を要求します。

Management canonical request digestは12章10節と同じ次のexact preimageです。ABI header、pointer、reserved、paddingを含めず、metadata lengthはu32です。

```text
resume_request_digest = SHA-256(
  ASCII("NINLIL-M1A-EVENT-RESUME") || transaction_id[16] ||
  operation_id[16] || actor_id[16] || expected_spool_revision:u64 ||
  resume_reason:u32 || metadata_length:u32 || metadata)

discard_request_digest = SHA-256(
  ASCII("NINLIL-M1A-EVENT-DISCARD") || transaction_id[16] ||
  operation_id[16] || actor_id[16] || expected_event_id[16] ||
  expected_content_digest_algorithm:u16 || expected_content_digest[32] ||
  expected_spool_revision:u64 || discard_reason:u32 ||
  acknowledge_required_receipt_absent:u32 || metadata_length:u32 || metadata)
```

`message_semantic_digest`はBearer C struct memoryでなく次のexact value digestです。

```text
SHA-256(ASCII("NINLIL-BEARER-MESSAGE-V1") ||
  kind:u32 || flags:u32 || transaction_id[16] || attempt_id[16] || event_id[16] ||
  source:PARTY || target:TARGET || service:SERVICE_IDENTITY || content_digest[32] ||
  generation:u64 || deadline_clock_epoch[16] || absolute_effect_deadline_ms:u64 ||
  evidence_grace_ms:u64 || required_evidence:u32 || receipt_stage:u32 ||
  disposition:u32 || effect_certainty:u32 || retry_guidance:u32 || cancel_kind:u32 ||
  retry_delay_ms:u64 || evidence_clock_epoch[16] || evidence_now_ms:u64 || evidence_trust:u32 ||
  payload_length:u32 || payload || evidence_length:u32 || evidence)
```

Kind-specific zero/empty ruleは12章5.4です。ORDERED_INGRESS、ATTEMPT、REVERSE_REPLYは参照BLOBをstreamしてこのdigestを再計算し、stored valueと一致させます。

## 6. Family 5: standalone health source

Current family 5 subtypeはexact 1個です。

| Subtype | Key identity | Body |
| ---: | --- | --- |
| `01 INTERNAL_INVARIANT` | marker ID128 | `reason:u32 + subject_kind:u16 + reserved:u16=0 + subject_digest[32] + first_clock_epoch[16] + first_at_ms:u64 + detail_digest[32]` |

Marker revisionは常に1、head witnessとprimary digestはzeroです。`subject_kind`はsubject complete keyのrecord roleで、family 3=`0x0300`、family 4=`0x0400`、family 6 current semantic subtype=`0x0600 | subtype`だけです。Family 1/2/5、witness subtype 7d..7f、unknown family/subtypeはcorruptです。`subject_digest`はそのcomplete keyの`KEY_DIGEST`で、namespace全体ならsubject kind/digestをともにzeroにします。Marker IDは`SHA-256(ASCII("NINLIL-DOMAIN-INVARIANT-V1") || reason:u32 || subject_kind:u16 || subject_digest[32])`の先頭16 bytesで、新しいEntropyを消費しません。既存別markerとID衝突してcomplete preimageが異なる場合はcorruptです。Aggregate health、counter/capacity exhausted、callback recovery、commit unknownはfamily 5へ重複保存しません。Raw Storage corruptionを発見した後にmarkerを書こうとしてはなりません。

## 7. Family 6 closed subtype catalog

Subtype `01`はfuture schema/migration marker用に予約し、v1 Coreは生成しません。Provider schema、key root version、Type 1 bindingの`storage_schema`がv1 schema truthです。

| Subtype | Name | Key identity | Max body |
| ---: | --- | --- | ---: |
| `10` | SERVICE | composite digest | 768 |
| `11` | SERVICE_QUOTA | composite digest | 512 |
| `20` | TRANSACTION_ANCHOR | transaction ID | 1536 |
| `21` | TRANSACTION_SEQUENCE_INDEX | u64 sequence | 64 |
| `22` | TRANSACTION_STATE | transaction ID | 512 |
| `23` | RESERVATION | composite digest | 512 |
| `24` | IDEMPOTENCY_MAP | composite digest | 512 |
| `25` | EVENT_ID_MAP | composite digest | 512 |
| `26` | SCHEDULER_OWNER | u64 owner sequence | 512 |
| `27` | ORDERED_INGRESS | u64 ordered sequence | 1536 |
| `30` | BLOB | composite digest | 3264 |
| `31` | ATTEMPT | composite digest | 512 |
| `32` | EVIDENCE_CELL | composite digest | 1024 |
| `33` | CANCEL_STATE | composite digest | 512 |
| `34` | ATTEMPT_ID_INDEX | attempt ID | 128 |
| `40` | DELIVERY | composite digest | 1024 |
| `41` | RESULT_CACHE | composite digest | 1024 |
| `42` | REVERSE_REPLY | composite digest | 3264 |
| `50` | EVENT_SPOOL | transaction ID | 1536 |
| `51` | RETRY_SUMMARY | composite digest | 768 |
| `52` | MANAGEMENT_LEDGER | composite digest | 1024 |
| `60` | BEARER_STATE | singleton | 64 |
| `61` | RETENTION_BASIS | composite digest | 512 |
| `62` | CLOCK_BASELINE | singleton | 64 |
| `63` | CLEANUP_PLAN | composite digest | 512 |
| `64` | ATTEMPT_REUSE_FENCE | singleton | 64 |
| `7d` | WITNESS_HEAD_INDEX | composite digest | 192 |
| `7e` | WITNESS_MANIFEST_CHUNK | composite digest | 3000 |
| `7f` | WITNESS_HEADER | composite digest | 384 |

### 7.1 Private integer registries

Public semantic field（transaction state/outcome/reason、Receipt stage、Disposition、effect certainty、retry guidance、cancel/result/resume/discard kind等）は12章のpublic integerをexact保存します。次だけがDomain Store private enumです。表にない値はcorruptです。

| Field | Closed values |
| --- | --- |
| reservation `owner_kind` | 1 SERVICE, 2 TRANSACTION, 3 INGRESS, 4 DELIVERY, 5 CALLBACK |
| scheduler `owner_kind` | 1 TRANSACTION, 2 DELIVERY, 3 INGRESS |
| `work_class` | 1 REDUCE, 2 DISPATCH, 3 TIMER, 4 CALLBACK, 5 CLEANUP, 6 RECOVERY |
| `ingress_state` | 1 PENDING |
| ingress `owner_binding_kind` | 1 EXISTING_TRANSACTION, 2 EXISTING_DELIVERY, 3 NEW_DELIVERY |
| `blob_kind` | 1 COMMAND_PAYLOAD, 2 EVENT_PAYLOAD, 3 INGRESS_PAYLOAD, 4 EVIDENCE, 5 REPLY |
| BLOB `blob_owner_kind` | 1 TRANSACTION, 2 INGRESS, 3 DELIVERY |
| `attempt_kind` | 1 COMMAND, 2 EVENT, 3 CANCEL |
| `attempt_state` | 1 PREPARED, 2 OBSERVED_SENT, 3 RESOLVED, 4 RECOVERY_REQUIRED |
| attempt `attempt_owner_kind` | 1 TRANSACTION, 2 DELIVERY |
| attempt `send_state` | 1 PREPARED, 2 RETRYABLE_NO_SEND, 3 SENT_POSSIBLE, 4 CLOSED_DENIED, 5 RECOVERY_REQUIRED |
| cancel `cancel_send_gate_state` | 1 NEVER_INVOKED, 2 WOULD_BLOCK_RETRYABLE, 3 INVOKED_CLOSED |
| evidence `cell_kind` | 1 SUMMARY, 2 RAW |
| evidence `cell_state` | 1 UNUSED, 2 MATERIALIZED |
| evidence `evidence_owner_kind` | 1 TRANSACTION, 2 DELIVERY |
| cancel `cancel_owner_kind` | 1 TRANSACTION, 2 DELIVERY |
| `cancel_state` | 1 NONE, 2 PENDING_REMOTE_FENCE, 3 FENCED_BEFORE_DISPATCH, 4 TOO_LATE_EFFECT_POSSIBLE |
| `delivery_state` | 1 INBOX_COMMITTED, 2 DELIVERY_STARTED, 3 DEFERRED_WAIT, 4 RESULT_COMMITTED, 5 DISPOSITION_COMMITTED, 6 RECOVERY_REQUIRED, 7 RECONCILE_WAIT, 8 CANCEL_TOMBSTONE_ONLY |
| delivery `creation_kind` | 1 APPLICATION_FIRST, 2 CANCEL_FIRST |
| `token_state` | 1 NONE, 2 ACTIVE, 3 CONSUMED, 4 EXPIRED, 5 RECOVERY_REQUIRED |
| `reply_kind` | 1 RECEIPT, 2 DISPOSITION, 3 CUSTODY, 4 CANCEL_RESULT |
| reply `send_state` | 1 PENDING, 2 WAITING_RETRY, 3 CLOSED_SENT_OR_UNKNOWN, 4 CLOSED_DENIED, 5 CLOSED_COUNTER_EXHAUSTED |
| `spool_state` | 1 ACTIVE, 2 PARKED_RETRY, 3 RELEASED, 4 DISCARDED |
| retry `summary_kind` | 1 CUMULATIVE, 2 RECENT |
| retention `subject_kind` | 1 SERVICE, 2 TRANSACTION, 3 DELIVERY, 4 EVENT |
| `retention_state` | 1 ACTIVE, 2 ELIGIBLE, 3 CLEANUP_COMMITTED |
| cleanup `cleanup_phase` | 1 DELETE_NON_INDEX, 2 DELETE_ATTEMPT_INDEX, 3 FINALIZE |
| witness `retention_kind` | 0 NONE, 1 SERVICE, 2 TRANSACTION, 3 DELIVERY, 4 EVENT |
| witness `witness_state` | 1 ACTIVE, 2 SUPERSEDED, 3 RETIRED |
| head index `index_state` | 1 BASELINE, 2 WITNESSED |
| clock baseline `baseline_state` | 1 UNINITIALIZED, 2 TRUSTED |

Reservation owner identityはexact 1つです。SERVICEは`service_key_raw`のcontents、TRANSACTIONは`transaction_id[16]`、INGRESSは`ordered_sequence:u64`、DELIVERYは`delivery_key_raw`のcontents、CALLBACKは`delivery_key_raw:RAW16 || token_generation:u64`を`owner_key_raw`のcontentsにします。Primaryは順にSERVICE、TRANSACTION_ANCHOR、ORDERED_INGRESS、DELIVERY、DELIVERYです。同じsemantic ownerはcanonical formulaにより0または1 RESERVATIONだけを持ち、別keyや別rawでの重複はcorruptです。NAMESPACE reservationはv1でunknown owner kindとしてcorruptです。

Scheduler subject rawはTRANSACTION=`transaction_id[16]`、DELIVERY=`delivery_key_raw` contents、INGRESS=`ordered_sequence:u64`です。Primaryは順にTRANSACTION_ANCHOR、DELIVERY、ORDERED_INGRESSで、ownerがINGRESSからDELIVERYへ移るreductionはSCHEDULER_OWNER value/common primary digestのreplacementとINGRESS erase/DELIVERY createを同じwitness groupへ含めます。Namespace/Bearer/recovery barrierはownerを作らず、owner kind外です。

BLOB owner mappingはTRANSACTION=`transaction_id[16]`→TRANSACTION_ANCHOR、INGRESS=`ordered_sequence:u64`→ORDERED_INGRESS、DELIVERY=`delivery_key_raw` contents→DELIVERYです。Allowed pairはCOMMAND/EVENT_PAYLOAD×TRANSACTIONまたはDELIVERY、INGRESS_PAYLOAD/EVIDENCE×INGRESS、REPLY×DELIVERYだけです。各owner/blob kind/content digest tupleは0または1 manifestを持ち、別blob ID aliasはcorruptです。

## 8. Exact subtype bodies

下表のfieldを記載順にencodeします。Optional IDはpresence u8の直後に置き、absentなら16-byte ID自体を省略します。Bodyのraw identityとkey digestはexact一致必須です。

### 8.1 Serviceとquota

- `SERVICE`: `service_key_raw:RAW16(max 255) + descriptor_revision:u64 + descriptor_digest[32] + local_application_instance_id[16] + namespace:TEXT_ID + service:TEXT_ID + schema:TEXT_ID + schema_major:u16 + minor_min:u16 + minor_max:u16 + family:u32 + direction:u32 + admission_authority:u32 + apply_contract:u32 + custody_policy:u32 + supported_evidence_mask:u32 + logical_payload_limit:u32 + target_limit:u32 + inflight_limit:u32 + attempts_per_cycle:u32 + admission_window_ms:u32 + max_admissions_window:u32 + max_payload_window:u32 + minimum_deadline_ms:u64 + maximum_deadline_ms:u64 + maximum_evidence_grace_ms:u64 + attempt_receipt_timeout_ms:u64 + retry_backoff_ms:u64 + application_completion_timeout_ms:u64 + required_dedup_window_ms:u64 + quota_key_digest[32] + reservation_key_digest[32]`。
- `SERVICE_QUOTA`: `service_key_raw:RAW16(max 255) + service_key_digest[32] + window_clock_epoch[16] + window_start_ms:u64 + admissions_in_window:u32 + payload_bytes_in_window:u64 + active_transaction_count:u32 + active_spool_count:u32 + active_spool_bytes:u64`。Common primary digestはSERVICE value、`service_key_digest`はcomplete SERVICE keyの`KEY_DIGEST`です。Receiver DELIVERYはorigin descriptor quotaへ数えません。

Quotaのactive transaction/spool/count/bytesはlive TRANSACTION RESERVATION contributionからexact再計算します。`admissions_in_window`と`payload_bytes_in_window`はcleanup済みtransactionから再構成しないwitness-protected authoritative fixed-window accumulatorで、window epoch/start、descriptor limits、checked increment/rollover、`payload_bytes >= 0`を検査します。Window rollover前まで全transaction recordを保持する追加契約を作らず、historical counterをlive sumと比較しません。

### 8.2 Transaction、index、reservation、mapping

- `TRANSACTION_ANCHOR`: `transaction_id[16] + transaction_sequence:u64 + scheduler_owner_sequence:u64 + family:u32 + source:PARTY + service:SERVICE_IDENTITY + content_digest[32] + canonical_submission_digest[32] + event_id[16] + generation:u64 + admission_clock_epoch[16] + admitted_at_ms:u64 + deadline_clock_epoch[16] + absolute_effect_deadline_ms:u64 + evidence_grace_ms:u64 + required_evidence:u32 + target_count:u32=1 + target:TARGET + idempotency_scope_raw:RAW16(max 255) + idempotency_key:RAW16(max 64) + sequence_index_key_digest[32] + idempotency_map_key_digest[32] + event_map_key_digest[32] + reservation_key_digest[32] + scheduler_owner_key_sequence:u64 + payload_blob_key_digest[32]`。DesiredStateではevent ID/map keyはzero、EventFactではnon-zeroです。
- `TRANSACTION_SEQUENCE_INDEX`: `transaction_sequence:u64 + transaction_id[16] + anchor_value_digest[32]`。
- `TRANSACTION_STATE`: `transaction_id[16] + anchor_value_digest[32] + state:u32 + outcome:u32 + deadline_verdict:u32 + latest_evidence:u32 + reason:u32 + event_park_cause:u32 + retry_cycle_id:u64 + attempt_in_cycle:u32 + cumulative_attempts:u64 + event_spool_revision:u64 + has_late_evidence:u32 + explicitly_discarded:u32 + target:TARGET + target_state:u32 + target_outcome:u32 + target_reason:u32 + target_latest_evidence:u32`。
- `RESERVATION`: `owner_kind:u16 + reserved:u16=0 + owner_key_raw:RAW16(max 255) + primary_key_digest[32] + resources:RESOURCE_VECTOR + service_inflight:u32 + grant_active_count:u32 + grant_active_bytes:u64 + released_mask:u32`。全Core-owned allocationを7.1のowner別recordにし、11 kind全部を保存します。Keyとbody ownerは5.1で再計算し、common primary digestはそのowner primary valueです。`released_mask` bit 0..10はresource kind 1..11、known mask `0x000007ff`だけです。Bitは0→1単調で、そのkindのused/reservedが両方zeroになったfinal releaseと同じFULL groupで立て、同ownerによる再取得を禁止します。Ownerが一度も保持しないkindのbitは0です。
- `IDEMPOTENCY_MAP`: `scope_raw:RAW16(max 255) + idempotency_key:RAW16(max 64) + transaction_id[16] + canonical_submission_digest[32] + anchor_value_digest[32]`。
- `EVENT_ID_MAP`: `scope_raw:RAW16(max 255) + event_id[16] + transaction_id[16] + canonical_submission_digest[32] + idempotency_key:RAW16(max 64) + anchor_value_digest[32]`。

### 8.3 Schedulerとingress

- `SCHEDULER_OWNER`: `owner_sequence:u64 + owner_kind:u16 + work_class:u16 + subject_key_raw:RAW16(max 255) + primary_key_digest[32] + state_revision:u64 + logical_clock_epoch[16] + logical_at_ms:u64 + next_wake_clock_epoch[16] + next_wake_at_ms:u64 + ready:u32`。`subject_key_raw`からTRANSACTION_ANCHOR / DELIVERY / ORDERED_INGRESS primary keyをowner kindどおりexact導出します。`owner_sequence`と`state_revision`は1以上、`logical_clock_epoch`はnon-zero、`ready`はu32 exact 0/1です。Next wakeはepoch/timeともzero（future timerなし）またはepoch non-zeroかつtime non-zero（future timerあり）のexact 2形だけです。Immediate workと別のfuture timerは同じownerに併存できるため、`ready=1`でも後者を許します。`state_revision`はowner stateのrevisionでありcommon `record_revision`とは別counterなので、同値を要求しません。
- `ORDERED_INGRESS`: `ordered_sequence:u64 + owner_sequence:u64 + owner_binding_kind:u16 + reserved:u16=0 + message_kind:u32 + message_flags:u32=0 + transaction_id[16] + attempt_id[16] + event_id[16] + source:PARTY + target:TARGET + service:SERVICE_IDENTITY + content_digest[32] + generation:u64 + deadline_clock_epoch[16] + absolute_effect_deadline_ms:u64 + evidence_grace_ms:u64 + required_evidence:u32 + receipt_stage:u32 + disposition:u32 + effect_certainty:u32 + retry_guidance:u32 + cancel_kind:u32 + retry_delay_ms:u64 + evidence_clock_epoch[16] + evidence_now_ms:u64 + evidence_trust:u32 + reserved:u32=0 + message_semantic_digest[32] + payload_blob_key_digest[32] + evidence_blob_key_digest[32] + ingress_state:u32=1 + reservation_key_digest[32]`。`message_kind`ごとの非該当fieldはzero、必須fieldとzero規則は12章Bearer message表とexact一致します。Evidence timeはepoch/now/trustのself-contained copyで、非Receiptでは全zeroです。EXISTING variantsはowner sequenceの既存TRANSACTION/DELIVERY ownerへattachしnew ownerを作らず、NEW_DELIVERYだけINGRESS-primary ownerを同じcopy groupで作りreduction時にDELIVERYへtransferします。これだけと参照BLOBからBearer semantic valueをbyte-for-byte再構成できなければcorruptです。ReductionはORDERED_INGRESSをREDUCEDへreplaceせず、reducer outputと同じFULL groupでeraseします。

### 8.4 Blob、attempt、evidence、cancel

`BLOB.flags` low 2 bitsは1=manifest、2=chunkです。Manifest/chunk keyは5.1のcomposite formulaだけを使います。

- BLOB manifest: `blob_id_digest[32] + blob_owner_kind:u16 + blob_kind:u16 + owner_key_raw:RAW16(max 255) + owner_primary_key_digest[32] + total_length:u64 + chunk_count:u32 + content_digest[32]`。Common primary digestはowner primary valueです。
- BLOB chunk: `blob_id_digest[32] + manifest_key_digest[32] + chunk_index:u32 + chunk_count:u32 + total_length:u64 + content_digest[32] + chunk_length:u32 + chunk_bytes[chunk_length]`。Common primary digestはmanifest complete value、`chunk_length<=3072`です。

Scannerはmanifestからindex 0..chunk_count-1をexact `get`し、全chunkのblob ID/manifest key/count/total/content digestをmanifestへexact照合します。Chunk bytesをindex順にstreaming SHA-256へ入れ、checked length sumが`total_length`、final digestがmanifest `content_digest`と一致しなければcorruptです。Zero lengthはcount 0かつSHA-256(empty)、それ以外はsection 2の非末尾/末尾length規則を満たします。Ownerが保持するBLOB key digestをmanifest complete keyへ、COMMAND/EVENT payloadはowner `content_digest`へ、INGRESS/EVIDENCE/REPLYは対応message/reply semantic fieldへ照合します。Chunk CRCや反復field一致だけでsemantic content検証を省略しません。
- `ATTEMPT`: `attempt_id[16] + attempt_owner_kind:u16 + reserved:u16=0 + owner_key_raw:RAW16(max 128) + primary_key_digest[32] + transaction_id[16] + target_digest[32] + attempt_kind:u16 + attempt_state:u16 + retry_cycle_id:u64 + attempt_in_cycle:u32 + cumulative_attempts:u64 + send_operation_generation:u64 + send_invocation_count:u64 + send_counter_exhausted:u32 + reserved:u32=0 + message_semantic_digest[32] + prepared_clock_epoch[16] + prepared_at_ms:u64 + send_state:u32 + availability_epoch:u64 + receipt_timeout_clock_epoch[16] + receipt_timeout_at_ms:u64`。TRANSACTION ownerはanchor、DELIVERY ownerはEndpoint deliveryをprimaryにします。Application attemptのsend return certaintyは`send_state`、remote cancelの再invocation可否はCANCEL_STATE gateを正本にします。Cached reverse sendはREVERSE_REPLYだけで管理しATTEMPTを作りません。
- `EVIDENCE_CELL`: `evidence_owner_kind:u16 + cell_kind:u16 + owner_key_raw:RAW16(max 128) + primary_key_digest[32] + target_digest[32] + slot_index:u32 + cell_state:u16 + reserved:u16=0 + highest_receipt_stage:u32 + latest_evidence_stage:u32 + material_receipt_stage:u32 + disposition:u32 + effect_certainty:u32 + late_material:u32 + issuer:PARTY + service:SERVICE_IDENTITY + content_digest[32] + generation:u64 + durable_ingress_sequence:u64 + evidence_clock_epoch[16] + evidence_at_ms:u64 + evidence_trust:u32 + counter_saturated:u32 + evidence_digest[32] + evidence_length:u16 + reserved:u16=0 + evidence_bytes[128] + valid_material_count:u64 + exact_duplicate_count:u64 + raw_overflow_count:u64 + late_evidence_count:u64`。TRANSACTION owner rawはtransaction ID、primaryはTRANSACTION_ANCHOR、DELIVERY owner rawはdelivery key contents、primaryはDELIVERYです。SUMMARYはslot 0/materialized、RAWはslot 1..Lでunused/materializedです。Unused RAWはidentity以外zero、SUMMARYはlatest/highest/issuer/time/dataと4 counterを保持します。RAW materializedはexact material tupleを保持しsummary counterはzeroです。Lengthは0..128、`[length,128)`はzeroです。Admission/Delivery admission時にsummary 1件とraw上限件を最大長fixed cellとしてmaterializeし、issuer/service/content/generation/time/ingress sequenceを含む13章のduplicate/latest/late判定を完全再構成します。
- `CANCEL_STATE`: `cancel_owner_kind:u16 + reserved:u16=0 + owner_key_raw:RAW16(max 128) + primary_key_digest[32] + transaction_id[16] + cancel_attempt_id[16] + cancel_state:u32 + cancel_kind:u32 + reason:u32 + effect_certainty:u32 + cancel_send_gate_state:u32 + message_semantic_digest[32] + timeout_clock_epoch[16] + timeout_at_ms:u64`。TRANSACTION ownerはController cancel、DELIVERY ownerはEndpoint cancel tombstoneです。GateはNEVER_INVOKED→WOULD_BLOCK_RETRYABLE→INVOKED_CLOSEDだけで、INVOKED_CLOSED後はcrash/restart/timeoutでもremote cancelを再送しません。
- `ATTEMPT_ID_INDEX`: `attempt_id[16] + transaction_id[16] + attempt_kind:u16 + reserved:u16=0 + attempt_record_key_digest[32] + attempt_creation_value_digest[32]`。Roleを問わずlocal RuntimeがEntropyから生成したApplication/cancel attemptだけexact 1件作り、common primary digestはそのlocal-origin TRANSACTION_ANCHORです。Controller DesiredState attemptとEndpoint EventFact attemptを含み、Endpointが受信したremote Application/cancel echo attempt、reverse replyは作りません。Creation digestはATTEMPT CREATE manifestのnew digestとexact一致するimmutable collision provenanceで、後のATTEMPT replacementではindexを更新しません。Recoveryはcurrent ATTEMPT key/bodyのattempt/transaction/owner bindingを別途検査します。Global retained collision lookupはこのdirect ID128 keyを使い、index/ATTEMPT/anchorを同じwitness groupでcreateし、eraseはsection 11のfenced cleanupだけで行います。

### 8.5 Delivery、result、reply

- `DELIVERY`: `delivery_key_raw:RAW16(max 128) + creation_kind:u16 + reserved:u16=0 + scheduler_owner_sequence:u64 + transaction_id[16] + event_id[16] + source:PARTY + local_target:TARGET + service:SERVICE_IDENTITY + content_digest[32] + generation:u64 + deadline_clock_epoch[16] + absolute_effect_deadline_ms:u64 + evidence_grace_ms:u64 + required_evidence:u32 + payload_blob_key_digest[32] + result_cache_key_digest[32] + reservation_key_digest[32]`。Attemptに依存しないimmutable logical binding anchorで、common revisionは1です。Logical keyは`source.runtime_id + source.application_instance_id + transaction_id + local_target.runtime_id + local_target.application_instance_id`だけで、attempt IDを含みません。同じkeyの全messageはevent ID/generation、service identity、content digest、deadline/evidence snapshotを含むbody bindingがexact一致しなければ同一Deliveryへmergeせずconflict/invalid ingressです。APPLICATION_FIRSTと先行CANCEL_REQUESTのCANCEL_FIRSTのどちらも同じcanonical key formulaを使い、同一keyのDELIVERYを2件作ることは禁止します。
- `RESULT_CACHE`: `delivery_key_raw:RAW16(max 128) + delivery_key_digest[32] + transaction_id[16] + delivery_count:u64 + application_seen:u32 + application_attempt_count:u32 + delivery_state:u32 + reply_count:u32 + token_context_id[16] + token_generation:u64 + token_clock_epoch[16] + token_expires_at_ms:u64 + delivery_started_clock_epoch[16] + delivery_started_at_ms:u64 + completion_expires_at_ms:u64 + callback_invocations:u64 + reconcile_invocation_count:u64 + reconcile_retry_generation:u64 + reconcile_not_before_clock_epoch[16] + reconcile_not_before_ms:u64 + application_result_kind:u32 + evidence_stage:u32 + disposition:u32 + reason:u32 + effect_certainty:u32 + retry_guidance:u32 + retry_delay_ms:u64 + evidence_cell_key_digest[32] + token_state:u32 + cancel_result_kind:u32 + completed_clock_epoch[16] + completed_at_ms:u64`。APPLICATION_FIRST admissionはseen 1/delivery count 0/attempt count 1/INBOX_COMMITTED、CANCEL_FIRSTはseen 0/count 0/attempt count 0/CANCEL_TOMBSTONE_ONLYでexact 1件作成します。`delivery_count`は12章のactual on_delivery callback開始回数で、`callback_invocations`および発行token generationとexact一致します。DELIVERY_START commitだけが両countをchecked +1し、そのpost値をtoken generationへ保存します。APPLICATION_FIRSTへのexact-binding duplicateでnew remote attempt IDを初めて観測した場合はDELIVERY-owned ATTEMPTを追加し`application_attempt_count`だけをchecked incrementし、delivery_count/inbox/callback/effectを変更しません。CANCEL_FIRSTへ後着APPLICATIONが来ても13章の`ABSENT + cancel tombstone`を維持し、DELIVERY/RESULT/ATTEMPTを変更せず、application_seen/countを進めず、cached FENCED resultの既存reply opportunityだけを利用できます。DEFERRED_WAITはactive token、RECONCILE_WAITはnon-zero `reconcile_retry_generation`とlocal not-before epoch/timeを必須とし、他stateの非該当timerはzeroです。RESULT/DISPOSITION terminalはresult tupleとcompleted timeを保持します。CANCEL_FIRSTはprivate physical anchorを持つ一方public Delivery/transaction queryへ常にABSENTとprojectします。Reply countは0..4でreply kindごと最大1です。Canonical reply keyはdelivery+reply kindだけで、semantic digestはbodyとしてreplacementし、同kindの別key増殖は禁止します。Duplicate opportunityは同じreply recordをreplaceしcountを増やしません。
- `REVERSE_REPLY`: `reply_key_raw:RAW16(max 192) + delivery_key_raw:RAW16(max 128) + transaction_id[16] + reply_kind:u32 + semantic_digest[32] + body_blob_key_digest[32] + send_state:u32 + send_operation_generation:u64 + send_invocation_count:u64 + send_counter_exhausted:u32 + reserved:u32=0 + attempt_id[16] + availability_epoch:u64 + retry_clock_epoch[16] + retry_not_before_ms:u64`。Common primary digestはDELIVERY complete valueです。Reply payloadはBLOBを参照し、inline opaque bytesを持ちません。`send_invocation_count`はactual call総数ではなく、Bearer return observationをdurably commitした回数です。`send_operation_generation`はTxGate TEMPORARY/DENIED/contract no-sendまたはBearer returnという各send micro-operation final observation commitごとにchecked +1するdurable ordinalで、kind 6 witness identityへ使います。Actual Bearer return variantだけ同じcommitでsend invocation countもchecked +1し、常に`send_invocation_count <= send_operation_generation`です。Send return後・observation前crashでは両count/stateを進めず、12章どおりsame immutable replyを再送できます。WAITING_RETRYだけtimer non-zero、PENDING/全closedではzeroです。State 3/4はexact duplicate inboundがsame semantic replyをPENDINGへ進めるnew opportunityを許しますが、state 5または`send_counter_exhausted=1`はabsorbingでduplicateでもreopenしません。Duplicate opportunityはcountをresetしません。

### 8.6 Event、management、namespace state

- `EVENT_SPOOL`: `transaction_id[16] + event_id[16] + spool_revision:u64 + spool_state:u32 + park_cause:u32 + retry_cycle_id:u64 + payload_blob_key_digest[32] + provider_id[16] + provider_revision:u64 + decision_digest[32] + grant_id[16] + grant_revision:u64 + decision_clock_epoch[16] + evaluated_at_ms:u64 + valid_from_ms:u64 + expires_at_ms:u64 + provider_retry_delay_ms:u64 + grant_limit_payload:u32 + grant_limit_active_count:u32 + grant_limit_active_bytes:u64 + grant_window_ms:u32 + grant_max_admissions_per_window:u32 + grant_attempts_per_cycle:u32 + last_seen_availability_epoch:u64 + last_consumed_availability_epoch:u64 + successful_resume_count:u32 + discard_committed:u32 + reservation_key_digest[32]`。Common primary digestはTRANSACTION_ANCHORです。Admission時のsource/application/service/target authorization tupleは同anchorのexact snapshotを参照し、decision fieldsと組み合わせて13章のgrant decisionを完全再検証します。Provider grantにbyte-window fieldはなく、descriptor payload-byte quotaと混同しません。`successful_resume_count`は0..8、`discard_committed`は0/1です。
- `RETRY_SUMMARY` CUMULATIVE: `transaction_id[16] + summary_kind:u16=1 + slot_index:u16=0 + total_completed_cycle_count:u64 + folded_cycle_count:u64 + cumulative_attempt_count:u64 + last_outcome:u32 + last_reason:u32 + last_ended_clock_epoch[16] + last_ended_at_ms:u64 + delivery_possible_any:u32 + counter_saturated:u32`。
- `RETRY_SUMMARY` RECENT: `transaction_id[16] + summary_kind:u16=2 + slot_index:u16(0..3) + retry_cycle_id:u64 + attempt_count:u32 + last_outcome:u32 + last_reason:u32 + availability_epoch:u64 + ended_clock_epoch[16] + ended_at_ms:u64 + delivery_possible:u32 + reserved:u32=0`。Common primary digestはどちらもTRANSACTION_ANCHORです。Completed cycleは`slot_index=(retry_cycle_id - 1) mod 4`へ保存し、既存slotをreplaceする前にそのold cycleをCUMULATIVEへchecked foldします。Always `recent_count=min(total_completed_cycle_count,4)`、`folded_cycle_count=max(total_completed_cycle_count-4,0)`です。CUMULATIVEはadmission時exact 1件、RECENTは0..4件で、5件を超えて増殖しません。Counter overflowはMAX維持+`counter_saturated=1`で、EventをCOUNTER_EXHAUSTED parkへ進めます。
- `MANAGEMENT_LEDGER`: `operation_id[16] + operation_kind:u16 + reserved:u16=0 + ordered_sequence:u64 + transaction_id[16] + event_id[16] + actor_id[16] + canonical_request_digest[32] + expected_spool_revision:u64 + expected_event_id[16] + expected_content_digest_algorithm:u16 + reserved:u16=0 + expected_content_digest[32] + request_reason:u32 + acknowledge_flag:u32 + audit_length:u16 + reserved:u16=0 + audit_bytes[128] + audit_clock_epoch[16] + audit_committed_at_ms:u64 + replay_result_kind:u32 + replay_result_reason:u32 + replay_retry_cycle_id:u64 + replay_spool_revision:u64 + replay_spool_released:u32 + reserved:u32=0`。Common primary digestはTRANSACTION_ANCHORです。Operation kindは15 EVENT_RESUMEまたは16 EVENT_DISCARDだけ、ordered sequenceはpublic management inputへ割り当てたnon-zero durable input sequenceでfamily 3 counter以下です。Content digest algorithmは0 NONE / 1 SHA-256です。Resumeではexpected event/content、ack、audit clock/time、releasedがzero、discardではalgorithm 1、ack 1、trusted audit clock/timeが必須です。Audit `[length,128)`はzeroです。Digest再計算時はpersist済みu16 lengthをchecked u32へ拡張して12章preimageへencodeします。

MANAGEMENT_LEDGERはEvent admission時に物理slotを作りません。成功したdistinct resume/discardのFULL mutationだけが`transaction_id || operation_id` composite keyのledgerを1件createし、Event spool/count、reservation vector、state/resultを同じwitness groupで更新します。Event spoolはresume最大8、discard最大1をguardし、RESERVATIONは未使用分をlogical `reserved`、作成済みledger分をlogical `used`としてexact 256/512 bytesずつ表します。Ledger hitはcanonical request digestとoperation kindを先に比較し、一致ならpersist済みreplay fieldをcurrent Event state/revisionを再評価せず返します。不一致はpublic conflict resultです。
- `BEARER_STATE`: `availability_epoch:u64 + available:u32 + observation_clock_epoch[16] + observed_at_ms:u64`。Absent before first observation、以後non-zero strictly increasing epochだけoperation kind 20 witnessでcreate/replaceします。Same/old epochはwrite 0、same epoch/different availableはcontract failureです。
- `RETENTION_BASIS`: `subject_kind:u16 + reserved:u16=0 + subject_key_raw:RAW16(max 255) + subject_primary_key_digest[32] + basis_clock_epoch[16] + basis_at_ms:u64 + exclusive_cleanup_at_ms:u64 + required_window_ms:u64 + retention_state:u32 + basis_pending:u32 + retention_overflow:u32`。Common primary digestはretained immutable subject complete valueです。M1aで生成するsubjectはTRANSACTIONとDELIVERYだけです。DesiredState/EventFactはともにTRANSACTION_ANCHORをrootとするTRANSACTION basis exact 1へ全attempt/index、Event spool/retry/managementを集約し、required windowは`terminal_retention_ms`です。Endpoint DeliveryはDELIVERY basis exact 1へresult/disposition/token/cancel/reply/evidenceを集約し、required windowは`result_cache_retention_ms`です。SERVICEはM1aにunregisterがないためbasis 0、EVENTはTRANSACTIONへ統合するためbasis 0です。BLOB/management/attemptはowner basisへ集約し独立basisを作りません。登録時guardにより各windowは該当service dedup要件以上で、stored `required_window_ms`がprofile値と異なればcorruptです。

Retention field matrixはclosedです。ACTIVE+pendingは`basis_pending=1`、overflow=0、epoch/time/delete-at zero。ACTIVE+overflowはpending=0、overflow=1、trusted non-zero epoch/basis time、delete-at zero。ACTIVE+trustedは両flag 0、non-zero epoch、`delete_at=checked(basis+window)`でcurrent trusted nowがexclusive end未満です。ELIGIBLEは両flag 0、同じtrusted basis/delete-atを保持し、eligibility判定sampleがsame epochかつnow>=delete-atとなるFULL replacementです。CLEANUP_COMMITTEDはPLAN_CREATEと同じwitnessでELIGIBLEからだけ進み、両flag 0とbasis/delete-atを保持してCLEANUP_PLAN `cleanup_generation`へpost-replacement record revisionを保存します。Plan存在中はexact CLEANUP_COMMITTED、FINALIZEでbasisとplanを同時eraseします。Pending/overflowからELIGIBLE/CLEANUP_COMMITTEDへ直接進めず、Clock epoch changeだけがfull windowをnew trusted sampleから再基準化し、same-epoch regressionはcreate/operation failureでrebaseしません。
- `CLOCK_BASELINE`: `baseline_state:u32 + reserved:u32=0 + trusted_clock_epoch[16] + last_trusted_now_ms:u64 + publish_generation:u64`。Metadata初期化はUNINITIALIZED/common revision 1、epoch/time/generation zeroを必ず作り、以後absentはcorruptです。最初のaccepted Stage 7 sampleはTRUSTED/common revision 2/generation 1へreplaceし、以後の各accepted sampleはsame/new epochともcommon revisionとgenerationをchecked +1してStage 8前にreplaceします。同epochでは`now >= last`、new epochでは任意のtrusted `now`を受理します。後続Bearer open等が失敗してpublic handleをpublishしなくてもbaselineを巻き戻さないため、`publish_generation`はpublish済みhandle数ではなくpublish-attempt用trusted sampleのdurable generationです。GenerationまたはrevisionがMAXならwrapせず`NINLIL_E_DEGRADED`、publish 0、Storage mutation 0です。COMMIT_UNKNOWNはold/new complete value digestで収束し、authoritative newを確認できるまでpublishしません。

Stage 7がstrictly new clock epochをcommitした場合、Stage 9前にfresh domain scanを行います。ATTEMPT receipt timeout、CANCEL timeout、TRANSACTION retry/deadline timer、RESULT token/reconcile timer、REVERSE_REPLY retry timer、RETENTION_BASISのnon-zero old epochをcomplete record keyごとのpriority 6 `CLOCK_UNCERTAIN` sourceとして導出します。Matching CLEANUP_PLANが存在しbasis state=CLEANUP_COMMITTEDのRETENTION_BASISだけはeligibilityが既にdurable確定しているためsource/rebase対象外で、plan phaseをepoch非依存に継続します。それ以外のmismatch subjectはtimer比較、callback completion、send、cleanupをfail closedし、old numeric timeをnew epochへ比較/換算しません。Active token/send effectを誤って再開しないためRESULT/CANCEL/ATTEMPTと必要なowner STATE/SPOOL/SCHEDULER companionはoperation kind 21のwitnessでRECOVERY_REQUIRED/parkへ進め、RETENTION_BASISはnew trusted sampleからfull durationをrebaseします。Createはpriority 6を含むDEGRADED Runtimeをpublishでき、`runtime_step`はこれらrecovery itemを通常effectより先に1件ずつ処理します。各valid recovery commitでそのrecord-key sourceだけclearし、全件解消後にCLOCK_UNCERTAINをclearします。
- `CLEANUP_PLAN`: `subject_kind:u16 + cleanup_phase:u16 + subject_key_raw:RAW16(max 255) + subject_primary_key_digest[32] + subject_primary_value_digest[32] + cleanup_generation:u64 + batch_generation:u64 + initial_attempt_count:u64 + remaining_attempt_count:u64 + initial_attempt_index_count:u64 + remaining_attempt_index_count:u64 + attempt_reuse_fenced:u32 + reserved:u32=0`。Common primary digestはcleanup対象immutable primaryです。M1a legal subject kindは2 TRANSACTIONまたは3 DELIVERYだけで、1 SERVICE/4 EVENTはcorruptです。`cleanup_generation`はplan create時のRETENTION_BASIS post-replacement common record revisionでimmutable、`batch_generation`はcreate=1、各phase/batch commitでchecked +1です。Initial countはPLAN_CREATE snapshotのsame-primary ATTEMPT / local ATTEMPT_ID_INDEX exact countでimmutable、remainingは各successful bounded batchが消したexact件数だけchecked減少し、増加やinitial超過は禁止です。Retention eligibility commit後にphase 1でcreateし、public query/listはplan存在subjectをlogically absentとして扱いますが、collision lookup/recoveryはphysical primaryをfinalizeまで保持します。
- `ATTEMPT_REUSE_FENCE`: `active_plan_count:u32 + reserved:u32=0 + fence_generation:u64`。Active count 1以上だけrecordが存在し、zeroでeraseします。Absent→first createのgenerationは1、present join/leave replacementはchecked +1、count 1→0ではrecordをeraseします。後に別cleanupでabsentから再createする場合もgeneration 1です。Fence単独mutation、MAX replacement、flagged planなしのpresent fence、flagged planがあるabsent fenceはcorruptです。Common primary digestはzeroです。Fence存在中はnew attempt Entropy allocationを`NINLIL_E_WOULD_BLOCK`で停止し、transaction ID allocationやreplay/recoveryは継続します。
- `WITNESS_HEAD_INDEX`: `index_state:u16 + reserved:u16=0 + member_key_digest[32] + member_key_length:u16 + reserved:u16=0 + member_key_bytes[member_key_length] + member_value_digest[32] + member_head_witness_digest[32]`。Memberはfamily 3 counter 4件またはfamily 4 capacity 11件、key lengthはexact 10です。BASELINEはhead zero/common head zero、WITNESSEDはnon-zero両head exact一致です。Common primary digestはzeroです。これはshared mutable recordにhead chainを与えるmetadataで、単独のsemantic truthではありません。

## 9. Primary/index/backlink rules

Secondary common headerは`primary_value_digest=VALUE_DIGEST(primary)`を持ち、bodyはprimary keyを再構成できるraw componentを持ちます。Primary common headerはzeroです。Witness header/chunkはoperation metadataであり、このprimary/secondary規則の例外として両方zeroです。

Zero primary digestはfamily 5 marker、SERVICE、TRANSACTION_ANCHOR、ORDERED_INGRESS、DELIVERY、BEARER_STATE、CLOCK_BASELINE、ATTEMPT_REUSE_FENCE、WITNESS_HEAD_INDEX、WITNESS_HEADER/CHUNKだけです。その他は下表のprimary digestがnon-zeroです。BLOB manifestはownerのsecondaryかつchunkのprimaryであり、manifest自身のcommon digestはowner value、chunkのcommon digestはmanifest valueです。

| Primary | Secondary | Cardinality / primaryからのproof | Secondaryからのexact primary key |
| --- | --- | --- | --- |
| SERVICE | SERVICE_QUOTA | exact 1、SERVICEのquota key digest | `service_key_raw` |
| SERVICE | SERVICE RESERVATION | exact 1、SERVICEのreservation key digest | owner kind SERVICE + owner raw |
| TRANSACTION_ANCHOR | SEQUENCE_INDEX | exact 1、anchorのsequence/key | `transaction_id` |
| TRANSACTION_ANCHOR | TRANSACTION_STATE | exact 1、same transaction ID | `transaction_id` |
| TRANSACTION_ANCHOR | IDEMPOTENCY_MAP | exact 1、anchorのraw scope/key | body transaction ID |
| TRANSACTION_ANCHOR | EVENT_ID_MAP | Event exact 1 / Command 0、anchorのscope/event | body transaction ID |
| TRANSACTION_ANCHOR | transaction RESERVATION | exact 1、anchor reservation key | owner raw transaction ID |
| TRANSACTION_ANCHOR | SCHEDULER_OWNER | exact 1、anchor owner sequence | subject raw transaction ID |
| TRANSACTION_ANCHOR | ATTEMPT/ATTEMPT_ID_INDEX/EVIDENCE/CANCEL/EVENT_SPOOL/BLOB | state/countでbounded、streaming subtype scan | owner kind TRANSACTION + transaction ID |
| ORDERED_INGRESS | optional new SCHEDULER_OWNER/RESERVATION/BLOB | owner bindingとviewでbounded | owner kind INGRESS + ordered sequence raw |
| DELIVERY | RESULT_CACHE/SCHEDULER_OWNER/RESERVATION/ATTEMPT/EVIDENCE/CANCEL/reply/BLOB | initial RESULT exact 1、他はstate/countでbounded scan | owner kind DELIVERY + `delivery_key_raw` |
| BLOB manifest | BLOB chunks | exact `chunk_count`、index 0..count-1 | manifest key digest + blob raw |
| TRANSACTION_ANCHOR | RETRY_SUMMARY/MANAGEMENT_LEDGER | cycle / successful countsでbounded、streaming subtype scan | body transaction ID |
| immutable subject | RETENTION_BASIS | stateに応じ0/1、streaming subtype scan | subject kind + subject raw |
| cleanup subject | CLEANUP_PLAN | retention前0、cleanup中exact 1 | subject primary key digest |

D3 missing-secondary proofは次のexact cardinalityを使います。`L`はaccepted profile `max_evidence_per_target`、countはsame primary digestを持つrowだけを数えます。

| Primary/state | Required secondary cardinality |
| --- | --- |
| SERVICE | QUOTA 1、SERVICE RESERVATION 1 |
| TRANSACTION_ANCHOR any retained | SEQUENCE_INDEX 1、STATE 1、IDEMPOTENCY_MAP 1、SCHEDULER_OWNER 1、TRANSACTION RESERVATION 1、EVIDENCE_CELL `L+1` |
| DesiredState transaction | EVENT_ID_MAP 0、EVENT_SPOOL 0、CANCEL_STATE 1。Application ATTEMPT count=`STATE.cumulative_attempts`、non-zero cancel attemptなら+1。ATTEMPT_ID_INDEX countはlocal ATTEMPT countと同じ |
| EventFact transaction | EVENT_ID_MAP 1、EVENT_SPOOL 1、CANCEL_STATE 0。ATTEMPT/ID_INDEX count=`STATE.cumulative_attempts`、MANAGEMENT_LEDGER count=`successful_resume_count + discard_committed`、RETRY_SUMMARYはCUMULATIVE 1 + RECENT `min(total_completed_cycle_count,4)` |
| ORDERED_INGRESS PENDING | INGRESS RESERVATION 1。NEW_DELIVERYならINGRESS-primary SCHEDULER_OWNER 1、EXISTING_TRANSACTION/DELIVERYならnew owner 0でowner sequenceの既存ownerをexact `get`。Payload/evidence viewごとにrequired BLOB 0/1 |
| DELIVERY APPLICATION_FIRST | RESULT_CACHE 1、SCHEDULER_OWNER 1、DELIVERY RESERVATION 1、EVIDENCE_CELL `L+1`。APPLICATION ATTEMPT count=`RESULT_CACHE.application_attempt_count`で1以上。DesiredStateはCANCEL_STATE 1、EventFactは0。Cancel attempt ID non-zeroならDELIVERY-owned CANCEL ATTEMPT +1。ATTEMPT_ID_INDEX 0、REVERSE_REPLY count=`RESULT_CACHE.reply_count` |
| DELIVERY CANCEL_FIRST | RESULT_CACHE 1、SCHEDULER_OWNER 1、DELIVERY RESERVATION 1、CANCEL_STATE 1、DELIVERY-owned CANCEL ATTEMPT 1、APPLICATION ATTEMPT 0、EVIDENCE_CELL 0、payload BLOB 0、ATTEMPT_ID_INDEX 0。RESULTはapplication_seen/count/attempt_count 0かつCANCEL_TOMBSTONE_ONLY、REVERSE_REPLY count=`RESULT_CACHE.reply_count` |
| DELIVERY_STARTED/DEFERRED_WAIT | CALLBACK RESERVATION 1、それ以外のDelivery stateは0 |
| BLOB manifest | chunks exact `chunk_count` |
| SERVICE / active TRANSACTION / active DELIVERY | RETENTION_BASIS 0。SERVICE/EVENT subject-kind recordはM1aでは常に0 |
| terminal DesiredState/EventFact TRANSACTION | subject_kind TRANSACTION RETENTION_BASIS exact 1 |
| terminal/cancel-only DELIVERY | subject_kind DELIVERY RETENTION_BASIS exact 1 |
| cleanup-eligible TRANSACTION/DELIVERY | CLEANUP_PLANはcreate前0、create後finalizeまでexact 1 |

SCHEDULER_OWNERはprimaryに保存したowner sequenceのdirect u64 key、EVIDENCEはslot 0..L、RETRY recentはslot 0..3、known 1:1 digest fieldはdirect keyを導出します。Variable ATTEMPT/REPLY/MANAGEMENTはstreaming countに加え、各secondary bodyのraw owner、primary digest、ID uniqueness/indexを照合します。Countだけ一致する別key/別owner代入はvalidになりません。

ATTEMPT_REUSE_FENCEは`attempt_reuse_fenced=1`のphase 2/3 CLEANUP_PLAN数と`active_plan_count`がexact一致し、count 0ならrecord absent、1以上ならpresentです。Phase 1 planはremaining attempt>=remaining indexかつfenced 0、phase 2はremaining attempt=remaining index>=1かつfenced 1、phase 3は両remaining 0で、initial index 0ならfenced 0、1以上ならFINALIZEまでfenced 1です。Fence generationはplan join/finalize leaveごとchecked +1で、同じFULL witnessにplan/fence transitionを含めます。

Exact 1/known-key relationshipは同じREAD_ONLY snapshotでprimary→secondary `get`とsecondary→primary `get`を行います。One-to-many relationshipは全row streaming passでsecondary→primary exact `get`し、primaryのdeclared count/stateに対するchecked count/digest aggregateを、必要ならsubtypeごとにscanを再開して照合します。RAM節約のため整合性を弱めず、計算量増加を許します。Scannerはprimary key/value digest、relationship kind、checked countだけをworkspaceへ保持し、全ID集合を保持しません。

SERVICE、TRANSACTION_ANCHOR、ORDERED_INGRESS、DELIVERY、BLOB manifestはimmutable primaryでcommon revision 1です。Mutable lifecycleはQUOTA/STATE/RESULT/EVENT等のsecondaryへ分離します。これによりprimary digest更新のfan-outを禁止します。Missing backlink、別primary value digest、primary key raw不一致、declared cardinality不一致、revision conflict、hash collision raw identity mismatch、orphan index/chunkはcorruptです。CLEANUP_PLAN absent時は上表の通常cardinality、plan present時だけsection 11 phase-specific decreasing setを適用します。PrimaryはFINALIZEまで残し、planなしpartial deletionを許しません。

Payload/reply BLOBだけはlifecycle-dependent 1→0です。Active TRANSACTION/EVENT_SPOOL、PENDING ORDERED_INGRESS、INBOX/DELIVERY_STARTED/DEFERRED/RECOVERY/RECONCILE DELIVERYのCOMMAND/EVENT payload、未送信 REVERSE_REPLYのREPLYではreferenced manifest exact 1を要求します。Required Receipt/discardでspool released、Delivery result/disposition terminalのpayload、reply closed後はowner/anchorのhistorical key digestを保持したままmanifest 0を許し、payload release stateとBLOB manifest/chunks eraseを同じwitness groupへ含めます。それ以外のmissing manifest、release stateなのに残るmanifest、ownerより先でないorphanはcorruptです。

## 10. Atomic witness v1

Multi-record semantic mutationはwitness header 1件とmanifest chunk 1..32件を同じFULL transactionへ含めます。新しいEntropy IDを作らず、admissionはtransaction ID、attemptはattempt ID、ingressはordered sequence、managementは`transaction_id[16] || operation_id[16]`、timer/reducerはowner/ordered-input/timer generationのcanonical bytesをoperation identity contentsとします。これをRAW16で包むため、別transactionが同じcaller operation IDを使ってもkey collisionしません。

Operation kindはclosed u16です。

| Value | Operation |
| ---: | --- |
| 1 | SERVICE_REGISTER |
| 2 | COMMAND_ADMISSION |
| 3 | EVENT_ADMISSION |
| 4 | INGRESS_COPY |
| 5 | ATTEMPT_PREPARE |
| 6 | SEND_OBSERVATION_AND_CURSOR |
| 7 | RECEIPT_OR_DISPOSITION |
| 8 | DELIVERY_ADMISSION |
| 9 | DELIVERY_START |
| 10 | APPLICATION_RESULT |
| 11 | CALLBACK_RECOVERY |
| 12 | CANCEL_PREPARE_OR_GATE |
| 13 | CANCEL_RESULT |
| 14 | OWNER_AUTOMATIC_TRANSITION |
| 15 | EVENT_RESUME |
| 16 | EVENT_DISCARD |
| 17 | CAPACITY_BLOCK_OR_RELEASE |
| 18 | RETENTION_CLEANUP |
| 19 | DESTROY_TOKEN_RECOVERY |
| 20 | BEARER_STATE_OBSERVATION |
| 21 | RECOVERY_ITEM_MUTATION |

`operation_identity:RAW16`のcontentsはkindごとにclosedです。`post_*_revision` / countはchecked mutation後の値です。

| Kind | Exact identity contents |
| ---: | --- |
| 1 | `service_complete_key_digest[32]` |
| 2 | `transaction_id[16]` |
| 3 | `transaction_id[16]` |
| 4 | `ordered_sequence:u64` |
| 5 | `attempt_complete_key_digest[32]` |
| 6 | `send_record_complete_key_digest[32] || post_send_operation_generation:u64` |
| 7 | `ordered_sequence:u64` |
| 8 | `ordered_sequence:u64` |
| 9 | `delivery_complete_key_digest[32] || token_generation:u64` |
| 10 | `delivery_complete_key_digest[32] || token_generation:u64` |
| 11 | `delivery_complete_key_digest[32] || reconcile_retry_generation:u64 || post_reconcile_invocation_count:u64 || phase:u16` |
| 12 | `cancel_complete_key_digest[32] || post_record_revision:u64 || phase:u16` |
| 13 | `ordered_sequence:u64` |
| 14 | `subject_primary_key_digest[32] || phase:u16 || post_state_revision:u64` |
| 15 | `transaction_id[16] || operation_id[16]` |
| 16 | `transaction_id[16] || operation_id[16]` |
| 17 | `resource_kind:u16 || post_capacity_epoch:u64 || post_blocked_state:u32` |
| 18 | `cleanup_plan_complete_key_digest[32] || cleanup_phase:u16 || post_batch_generation:u64` |
| 19 | `runtime_id[16] || clock_publish_generation:u64` |
| 20 | `availability_epoch:u64` |
| 21 | `target_complete_key_digest[32] || expected_old_value_digest[32] || recovery_action:u16` |

同じkind/identityは同じlogical mutationのretryだけに使用し、別write-setならcontract failureです。Kind 6/11/12/14/17/18のpost値、kind 19のgeneration、kind 20のepochはdurable sourceから再構成でき、COMMIT_UNKNOWN後にnew Entropyやclock sampleで作り直しません。Kind 6はApplication ATTEMPTまたはREVERSE_REPLYの各send micro-operation final observationだけです。TxGate TEMPORARY/DENIED/contract no-sendとBearer returnの全variantがsend operation generationをchecked +1し、そのpost generationをidentityへ使います。Bearer return variantだけsend invocation countもchecked +1します。Generation/count MAXで次operationを作らずCOUNTER_EXHAUSTEDへfail closedします。Kind 6にpre-send semantic commitはなく、TxPermit acquisition/actual call後・observation前crashは12章のmessage-kind別再送/fence規則へ従います。Cancel REQUESTのconservative pre-send gate/WOULD_BLOCK observationだけはkind 12です。Kind 11 phaseは1 RECONCILE_CLAIM、2 RECONCILE_RESULT、3 CALLBACK_FAILURE_FENCE、kind 12 phaseは1 CANCEL_PREPARE、2 SEND_GATE_CLOSE、3 WOULD_BLOCK_REOPEN、4 CANCEL_TERMINALです。Kind 14 phaseは1 COMMAND_ATTEMPT_TIMEOUT、2 COMMAND_EVIDENCE_CLOSE、3 COMMAND_DEADLINE_TERMINAL、4 EVENT_TIMEOUT_OR_PARK、5 EVENT_AVAILABILITY_RESUMEです。Post state revisionはTRANSACTION_STATEのpost common revisionで、phase 4/5ではEVENT_SPOOL post revisionとのexact同時更新も要求します。Reconcile CLAIMはcallback前にinvocation countをdurable incrementし、RESULTは同じretry generation/invocationを参照します。Kind 17はadmission rejection等でRESERVATIONがまだ無いBLOCK_SETも表現し、blocked stateは0/1です。Kind 21 recovery actionは1 REPLACE_OLD_TO_NEW、2 ERASE_RETIRED、3 RECREATE_REQUIRED_INDEXだけです。

Kind 6 counter headroomはproactiveに閉じます。どちらかのpost counterがUINT64_MAXへ到達する最後のvalid observation commitは同じgroupで`send_counter_exhausted=1`を固定し、以後new send micro-operationを作りません。ATTEMPTで通常post-stateがfuture retryを必要とする場合はownerをCOUNTER_EXHAUSTED park/fail-closedへ進め、accepted/unknown/terminal observationならbusiness certainty/outcomeを上書きせずSEND_COUNTER health sourceだけを残します。REVERSE_REPLYはBearer resultに関係なくstate 5 CLOSED_COUNTER_EXHAUSTED、timer zeroへ進め、reply BLOBを同じwitnessでeraseします。Delivery RESULTのapplication result/reason/effect certaintyは上書きしません。Flagは0→1だけで、counter MAXかつflag 0、MAX未満でflag 1、flag reset、state 5でflag 0はcorruptです。「MAXで次operationを作らない」は別のoverflow commitを行う意味ではありません。

### 10.0 Canonical member-set builders

各operation kindは12/13章のlegal triggerとpost-stateを入力し、下表のnamed builderだけでmember setを作ります。Builderはfresh snapshotからcanonical post-stateを1つ導出し、許可roleのうちpresenceまたはcomplete encoded valueが変わるkeyだけをCREATE/REPLACE/ERASEへ入れます。変更するfamily 3/4 keyには対応HEAD_INDEXを必ず加え、変更memberが指すdistinct ACTIVE predecessor headerをSUPERSEDE_WITNESSとして加えます。許可role外の変更、必要keyの省略、no-op member、同じkind/identityから異なるkey set/value digestを作ることはcontract failureです。表のceilingはHEAD_INDEXと最大distinct predecessorを含み、header/chunk自身は含みません。

| Kind | Builder | Permitted semantic mutation roles | Member ceiling |
| ---: | --- | --- | ---: |
| 1 | `build_service_register` | SERVICE, SERVICE_QUOTA, SERVICE RESERVATION, SERVICE capacity | 16 |
| 2 | `build_command_admission` | counters, ANCHOR/SEQUENCE/STATE/IDEMPOTENCY, transaction RESERVATION/SCHEDULER, EVIDENCE, CANCEL, payload BLOB, SERVICE_QUOTA, capacities | 48 |
| 3 | `build_event_admission` | kind 2 roles + EVENT_ID_MAP, EVENT_SPOOL, RETRY_SUMMARY | 56 |
| 4 | `build_ingress_copy` | ordered/owner counters, ORDERED_INGRESS, optional ingress SCHEDULER/RESERVATION/BLOB, capacities | 32 |
| 5 | `build_attempt_prepare` | ATTEMPT, local ATTEMPT_ID_INDEX, TRANSACTION_STATE/EVENT_SPOOL/RESULT_CACHE/CANCEL_STATE, SCHEDULER/cursor, capacities | 24 |
| 6 | `build_send_observation` | ATTEMPT or REVERSE_REPLY, optional reply BLOB erase, owner STATE/SPOOL/RESULT/CANCEL, SCHEDULER/cursor | 24 |
| 7 | `build_receipt_or_disposition` | ORDERED_INGRESS erase, STATE/RESULT/EVIDENCE/SPOOL/ATTEMPT/REPLY/BLOB, owner/cursor, reservations/capacities | 48 |
| 8 | `build_delivery_admission` | ORDERED_INGRESS erase, DELIVERY/RESULT/CANCEL/remote ATTEMPT/EVIDENCE/payload BLOB, cached REVERSE_REPLY/reply BLOB, RETENTION_BASIS, DELIVERY RESERVATION/SCHEDULER, counters/capacities | 64 |
| 9 | `build_delivery_start` | RESULT_CACHE, DELIVERY/CALLBACK RESERVATION, SCHEDULER/cursor, token/result capacities | 24 |
| 10 | `build_application_result` | RESULT_CACHE, token RESERVATION release, RETENTION_BASIS, REVERSE_REPLY/BLOB, SCHEDULER/cursor, capacities | 32 |
| 11 | `build_callback_recovery` | RESULT_CACHE, RETENTION_BASIS, REVERSE_REPLY/BLOB, token RESERVATION, SCHEDULER/cursor, capacities | 24 |
| 12 | `build_cancel_prepare_or_gate` | CANCEL_STATE, ATTEMPT, local ATTEMPT_ID_INDEX, owner STATE/RESULT, REVERSE_REPLY/BLOB, SCHEDULER/cursor | 24 |
| 13 | `build_cancel_result` | ORDERED_INGRESS erase, CANCEL_STATE, owner STATE/RESULT, REVERSE_REPLY/BLOB, RETENTION_BASIS, cursor/capacities | 32 |
| 14 | `build_owner_automatic_transition` | TRANSACTION_STATE, optional EVENT_SPOOL/ATTEMPT/EVIDENCE/RETRY_SUMMARY/BLOB/RETENTION_BASIS, RESERVATION, SCHEDULER/cursor, capacities | 48 |
| 15 | `build_event_resume` | ordered counter, MANAGEMENT_LEDGER, STATE/SPOOL/RETRY/RESERVATION, SCHEDULER/cursor, capacities | 32 |
| 16 | `build_event_discard` | kind 15 roles + payload BLOB erase, RETENTION_BASIS, terminal resource release | 48 |
| 17 | `build_capacity_block_or_release` | one family 4 capacity key and its HEAD_INDEX only | 8 |
| 18 | `build_retention_cleanup` | CLEANUP_PLAN phase rules、eligible subject rows、optional ATTEMPT_REUSE_FENCE、quota/counter/capacity companions | 256 |
| 19 | `build_destroy_token_recovery` | bounded active-token RESULT_CACHE/CALLBACK RESERVATION set、shared capacities/owners | 160 |
| 20 | `build_bearer_state_observation` | BEARER_STATE only | 8 |
| 21 | `build_recovery_item_mutation` | identityが指すsingle target、owner TRANSACTION_STATE/EVENT_SPOOL/RESULT_CACHE/CANCEL_STATE/ATTEMPT/REVERSE_REPLY/SCHEDULERのrequired park/recovery transition、index/reservation/capacity/RETENTION_BASIS companion | 16 |

Optional roleは12/13章のpost-state predicateがtrueの場合だけ存在し、builder裁量ではありません。D1 vector generatorはkind/phaseごとにbase semantic member、family 3/4 HEAD companion、distinct ACTIVE predecessorを別々に数え、上表超過を仕様失敗としてCIで検出します。

Witness header metadataもbuilder裁量ではありません。

| Kind | `subject_id` source | `retention_kind` / subject key digest |
| ---: | --- | --- |
| 1 | SERVICE complete key digest先頭16 | 0 / zero |
| 2, 3, 15, 16 | transaction ID | 2 / TRANSACTION_ANCHOR complete key digest |
| 4 | ORDERED_INGRESS complete key digest先頭16 | EXISTING_TRANSACTION=2/anchor、EXISTING_DELIVERY=3/delivery、NEW_DELIVERY=0/zero |
| 5 | ATTEMPT complete key digest先頭16 | owner TRANSACTION=2/anchor、DELIVERY=3/delivery |
| 6 | ATTEMPTまたはREVERSE_REPLY complete key digest先頭16 | semantic owner TRANSACTION=2/anchor、DELIVERY=3/delivery |
| 7 | ORDERED_INGRESS complete key digest先頭16 | bound owner TRANSACTION=2/anchor、DELIVERY=3/delivery、invalid no-owner drop=0/zero |
| 8, 9, 10, 11 | DELIVERY complete key digest先頭16 | 3 / DELIVERY complete key digest |
| 12 | CANCEL_STATE complete key digest先頭16 | owner TRANSACTION=2/anchor、DELIVERY=3/delivery |
| 13 | ORDERED_INGRESS complete key digest先頭16 | 2 / Controller TRANSACTION_ANCHOR complete key digest |
| 14 | TRANSACTION_ANCHOR complete key digest先頭16 | 2 / TRANSACTION_ANCHOR complete key digest |
| 17 | family 4 capacity complete key digest先頭16 | 0 / zero |
| 18 | cleanup subjectがID128ならそのID、それ以外はprimary key digest先頭16 | plan subject TRANSACTION=2/anchor、DELIVERY=3/delivery |
| 19 | runtime ID | 0 / zero |
| 20 | BEARER_STATE complete key digest先頭16 | 0 / zero |
| 21 | target complete key digest先頭16 | target owner TRANSACTION=2/anchor、DELIVERY=3/delivery、namespace/witness metadata=0/zero |

Kind 19だけはruntime単位のbounded multi-delivery recoveryでsingle semantic subjectを持たないためretention 0です。他kindで表にないvariant、non-zero retentionとzero subject digest、または表と異なるsubject IDはcontract failureです。12章17節のnamed FULL hook pairはhook名でbuilderを選ばず、そのhookが囲むsemantic boundaryに従い上表kindへexact 1つ対応します: service register=1、Command/Event admission=2/3、ingress copy=4、attempt prepare=5、post-send observation/cursor=6、Receipt/Disposition reduction=7、Endpoint delivery/cancel-first admission=8、DELIVERY_STARTED=9、application result/token invalidation=10、callback/reconcile recovery=11、cancel prepare/send gate=12、cancel result reduction=13、Command attempt timeout/evidence close/pre-dispatch deadline terminalとEvent timeout/park/automatic availability resume=14、explicit management resume=15、discard=16、capacity block/release=17、retention cleanup=18、destroy token recovery=19、Bearer state=20、Stage-5/clock recovery item=21。Automatic availability resumeはcaller operation IDを生成せずkind 14 phase 5を使い、kind 15はnon-zero persisted management operation IDを持つexplicit resume専用です。Hook pairとsemantic boundaryがこのmappingへ一意に落ちない場合は新hookを推測せず仕様不備です。

Namespace bootstrapはfamily 1〜4 exact 17-record all-present/all-absent規則、identity/clock baselineはsingle-record old/new規則を使うため、このoperation kindを使いません。Witness memberにできるfamily 3/4は`record_role=(family << 8)`、family 5/6は`(family << 8) | subtype`としてencodeします。Family 1/2をmanifest memberにしません。

Witness key identity / `witness_digest`は5.1のWITNESS_HEADER composite digestです。Header encoded valueのdigestをkeyやmember headに使いません。

`WITNESS_HEADER` body:

```text
operation_kind       u16
witness_state        u16  # 1 ACTIVE, 2 SUPERSEDED, 3 RETIRED
operation_identity   RAW16, max 128
subject_id           16 bytes
canonical_digest     32 bytes
member_count         u16, 1..256
chunk_count          u16, ceil(member_count/8), 1..32
manifest_digest      32 bytes
retention_kind       u16
reserved             u16 = 0
retention_subject_key_digest 32 bytes
successor_witness_digest 32 bytes
```

ACTIVEでは`successor_witness_digest` zero、SUPERSEDED/RETIREDでは最初にsupersedeしたnon-zero successor witnessです。`WITNESS_MANIFEST_CHUNK` key identityは5.1のcomposite formula、body prefixは`witness_digest[32] + chunk_index:u16 + chunk_count:u16 + entry_count:u16 + reserved:u16=0`です。非末尾entry countは8、末尾は1..8です。

`subject_id`はoperationのsingle semantic subjectがID128ならそのID、u64/composite/singletonならそのcomplete keyの`KEY_DIGEST`先頭16 bytesです。全zeroは禁止します。

Header `canonical_digest`はstate/successor進行で変えないoperation write-set identityです。

```text
SHA-256(ASCII("NINLIL-DOMAIN-OPERATION-V1") ||
  operation_kind:u16 || operation_identity:RAW16 || subject_id[16] ||
  manifest_digest[32] ||
  retention_kind:u16 || retention_subject_key_digest[32])
```

Retention kind 0ではsubject key digest zero、1..4ではnon-zero `KEY_DIGEST`です。M1aが新規生成するretention kindはTRANSACTION=2とDELIVERY=3だけです。

各member entryは次のexact variable encodingです。

```text
record_role       u16
action            u8   # 1 CREATE, 2 REPLACE, 3 ERASE, 4 SUPERSEDE_WITNESS
reserved          u8 = 0
key_length        u16, 1..255
reserved          u16 = 0
key_bytes         key_length bytes
old_present       u8, 0/1
new_present       u8, 0/1
reserved          u16 = 0
prior_head_witness_digest 32 bytes
old_value_digest  32 bytes, absentならzero
new_value_digest  32 bytes, absentならzero
```

Entryはkey unsigned-byte lexicographic順です。Manifest digestは5.1のdomain-separated formulaです。Family 5/6 semantic REPLACE/ERASEでは`prior_head_witness_digest`がold complete valueのcommon headとexact一致します。Family 3/4では対応するold WITNESS_HEAD_INDEXのhead、BASELINEだけzeroです。CREATEとwitness metadata memberではzeroです。Member count/chunk count、actionとpresenceの組合せ、digest zero/non-zeroが矛盾すればcorruptです。

Manifest member keyはcurrent private keyspaceのfamily 3/4/5/6だけです。Family 3/4はlength 10、family 5/6は13..45で5節grammarにexact一致します。`record_role` high byteはkey family、family 5/6 low byteはkey subtypeと一致し、family 3/4 low byteはzeroです。Key length 1..255はwire field capacityであり、上記legal length外、family 1/2、別root/future root、role/key mismatchを受理する許可ではありません。

CREATEはold=0/new=1、REPLACEはold=1/new=1かつdigest不一致、ERASEはold=1/new=0だけです。SUPERSEDE_WITNESSはfamily 6 subtype 7f headerだけに使い、old/new=1、old ACTIVE、new SUPERSEDED、new successor=this witnessをexact encodeします。No-op member、同じkeyの重複、256件超過はCore contract failureです。

Unbounded lifetime Event attempt/indexはterminal cleanup 1 groupへ詰めません。Section 11のCLEANUP_PLANがbounded batchへ分けます。各batch builderはsemantic candidate、plan/fence/capacity/cursor mutation、distinct ACTIVE predecessor headerを追加する前にtotalをcheckedし、256を超えるcandidateを次batchへ残します。Candidate 1件でも固定overhead込み256以下なので必ずforward progressし、header/manifest chunks自身はmember count外です。Non-cleanup named operationはprofile上64 members以下、destroy active token groupは32 tokenに各state/reservationとshared metadataを加えて160以下です。D1 catalog testがoperation別exact上限を再導出します。

Recovery判定:

| Snapshot | Result |
| --- | --- |
| 全memberがold presence/digest、witness header/chunk全てabsent | not applied |
| ACTIVE header/chunk完全、全semantic memberがnew presence/digest一致。Family 5/6 semantic memberのhead、family 3/4対応HEAD_INDEXのhead/value digestはwitness/member new digest。SUPERSEDE_WITNESS memberは下記progression | applied / current head |
| SUPERSEDED header/chunk完全、successor witness完全、そのmanifestにこのheaderのACTIVE→SUPERSEDED exact replacementが存在。Current headがまだこのwitnessのmemberはmanifest new digestと一致 | applied / partially current historical |
| RETIRED header、current semantic head参照0。Incoming predecessor successor参照ありなら全chunk complete、参照0なら任意のcleanup-in-progress subset | applied / cleanup eligible |
| all-oldだがACTIVE witness完全に存在 | corrupt |
| old/new混在、ACTIVE/SUPERSEDED chain partial、ACTIVE header/chunk partial、digest/revision conflict | corrupt |
| recognizable future witness versionだけ | unsupported |

Provider FULL atomicityによりoperation commit境界はall-old/absentまたはall-new/completeだけで、SUPERSEDED/RETIREDは後続のcomplete transitionでのみ到達します。判定不能をretry可能な失敗へ弱めません。

### 10.1 Successor chain

Bootstrap 17-record create後、Stage 5はbusiness/domain recordが0件であることを証明してからfamily 3 counter 4件+family 4 capacity 11件に対するBASELINE WITNESS_HEAD_INDEX 15件とUNINITIALIZED CLOCK_BASELINE 1件を1 FULL transactionで作ります。0/16は未初期化、16/16 exactは初期化済み、1..15/16、business/domain rowありで0/16、index member digest不一致はcorruptです。COMMIT_UNKNOWNは0/16または16/16だけへ収束します。このgroupはsemantic mutation前のone-time metadata initializationなのでwitnessを使いません。Family 1 immutable profileとfamily 2 single identity replacementにはindexを作りません。

以後family 3/4 recordをmulti-record witness memberとしてREPLACEする場合、同じFULL groupに対応WITNESS_HEAD_INDEX replacementを必ず含めます。初回business mutationはBASELINE→WITNESSED、以後はindex value/headをnew member digest/current witnessへ進めます。Persistent counter/capacity indexのeraseは禁止です。Recoveryはindex→member exact `get`、member→index exact `get`を行い、indexだけ/memberだけ、value digest不一致、head不一致をcorruptとします。これによりshared counter/capacityをW2が更新するときもold indexからW1を発見し、W1を同じgroupでSUPERSEDEDへ進められます。

新しいwitness `W2`が、current head `W1`を持つsemantic memberをREPLACE/ERASEする場合、`W2`のFULL groupはmemberのnew headを`W2`へ進めます。`W1`がACTIVEなら、そのheaderをACTIVE→SUPERSEDEDへreplaceし、`successor_witness_digest=W2`を保存し、そのheader replacement自体をW2 manifestへ`SUPERSEDE_WITNESS` actionで含めます。複数memberが別のACTIVE predecessorを持つ場合はdistinct predecessor全てを同じgroupでsupersedeします。すでにSUPERSEDEDのpredecessor headerは再更新しません。

したがってcrash後は、W2全体が不在でW1 ACTIVEのold truthか、W2全体とW1 SUPERSEDEDのnew truthだけです。W2 member上限256はsemantic member、supersedeするpredecessor header、family 3/4 memberとHEAD_INDEXを全て含めてchecked導出します。Witness自身のheader/chunkは自分のmanifestへ含めません。

Successorはself不可、digest collision不可、chain cycle不可です。SUPERSEDED headerごとにsuccessor manifest内のold/new header digestとstate transitionをexact検査し、successor missing、別successor、ACTIVEへの逆行、SUPERSEDEDの再supersedeはcorruptです。Chain検査も全header集合をRAMへ置かず、起点ごとのbounded walkとfresh exact `get`で行い、visited stepがwitness row countを超えたらcycleとしてcorruptです。

Every current family 5/6 semantic headとfamily 3/4 HEAD_INDEX headは、complete ACTIVEまたはSUPERSEDED headerを指さなければなりません。SUPERSEDEDを指すcurrent memberはそのwitness manifestに同keyのnew entryがあり、current value digestがentry new digestと一致することを要求します。RETIRED/absent witnessをcurrent headが指す、manifestにないkeyがheadを指す、同keyだがdigest不一致はcorruptです。SUPERSEDED witnessは「全memberがhistorical」を意味せず、successorで進んだmemberと旧headを保つmemberの混在を明示的に許します。

`SUPERSEDE_WITNESS` entryは普通のsemantic memberと違い、後続cleanupを許すhistorical transitionです。Current predecessor headerがmanifestのexact SUPERSEDED valueなら直接一致、同じsuccessorを保持するvalid RETIRED valueならprogressed、header/chunkが全てabsentならcleanup済みとして一致します。別successor、ACTIVE、header absent + orphan chunk、partial ACTIVE/SUPERSEDED、incoming参照ありRETIRED partialはcorruptです。このprogression規則によりW1をretire/cleanupしてもW2 manifestを破損扱いしません。

### 10.2 Witness retentionと有限回収

Memberのcurrent revisionがhead witnessを参照する間、witnessを削除しません。Fresh full scanでcurrent semantic headからの参照が0と証明できたSUPERSEDED headerだけを、single-record FULL replacementでRETIREDへ進めます。ACTIVE→RETIREDを禁止します。Replacement COMMIT_UNKNOWNはold SUPERSEDED/new RETIRED headerのexact digestで収束できます。

RETIRED headerはsemantic truthではありません。ただし別のSUPERSEDED/RETIRED predecessor headerが`successor_witness_digest`でこのwitnessを参照する間はsuccessor proofなので、headerと全chunkをcompleteで保持します。Incoming predecessor successor参照が0とfresh scanで証明できた後だけ、headerを保持したままmanifest chunkを1 keyずつ消し、全chunk absentをfresh snapshotで確認してheaderをsingle-key eraseします。したがってcleanupはchainの古いpredecessor側から進みます。各single-key COMMIT_UNKNOWNはold/new presenceで収束します。Incoming参照0で途中crashしたRETIRED header + chunk subsetはvalid cleanup-in-progressです。Header不在のorphan chunkはretiredと証明できないためcorruptであり、cleanup debrisとして消してはなりません。ACTIVE/SUPERSEDED、またはincoming参照ありRETIRED headerのpartial chunkはcorruptです。

## 11. Retention rules

- Transaction anchor/state/target/reservation/mapping/index/evidence/attempt/indexはterminal retention exclusive endまでlogical retention対象
- Result cache、Delivery token/disposition/cancel/replyはresult-cache retention exclusive endまでlogical retention対象
- Event spool/payload/mappingはrequired receiptまたはexplicit discardのdurable commitまで期限削除禁止
- Service recordはunregister commit後もrequired dedup windowと参照transactionの長い方まで保持
- Retention basisはterminal subjectごとexact 1件で、Clock epoch change時だけfull durationを再基準化する。Pending/overflowは削除不可
- Blob manifest/chunkはowner release stateと同じwitness、またはcleanup plan FINALIZEだけで削除
- 成功したManagement ledgerは最大8 resume / 1 discardをEventのsingle retention basis終了まで保持。未使用logical slotにphysical recordは存在しない

Exclusive end到達後のcleanupは次のrestart-safe state machineです。Planなしsubjectへpartial deleteを行いません。

1. `PLAN_CREATE`: immutable primary、ELIGIBLE RETENTION_BASIS、全backlinkがcompleteなfresh snapshotだけから、basisをCLEANUP_COMMITTEDへreplaceしCLEANUP_PLAN phase 1 / batch generation 1を同じwitnessでcreateします。Plan `cleanup_generation`はbasisのpost-replacement revisionです。SnapshotでATTEMPTとlocal ATTEMPT_ID_INDEXをcountし、initial/remainingへ同値保存します。このcommitでは他child/resourceを削除せずfenced=0です。以後public query/listはsubjectをlogically absentとして扱います。Matching retained idempotency key、transaction ID、logical delivery keyへのnew admission/ingressはFINALIZEまで`NINLIL_E_WOULD_BLOCK` / retryへ収束し、old result replay、new owner create、callback、effectは0です。Binding不一致は既存conflict規則を維持します。Transaction/attempt collision lookupはphysical key/indexを使い続けます。
2. `DELETE_NON_INDEX`（phase 1）: 0-byte global scanからsame primaryのうちdirect attempt-ID lookupでATTEMPT_ID_INDEXが存在しないremote-origin ATTEMPTだけをunsigned-key順に選び、最大bounded prefixをeraseします。各batchは消した件数だけremaining attemptをchecked減算しbatch generationを+1し、remaining indexは不変です。したがって全index→ATTEMPT backlinkは通常どおり常に存在し、`remaining_attempt_count >= remaining_attempt_index_count`です。EVIDENCE/BLOB/management/retry/reply/state/maps/reservation等はFINALIZEまでexact通常cardinalityを保持します。Remote ATTEMPTが0、すなわち両remaining countが一致したcommitで、remaining indexが1以上ならphase 2へ進めてATTEMPT_REUSE_FENCEをcreate/replace、active plan countを+1、fenced=1とします。両countが0ならphase 3/fenced 0へ進みます。Fence transitionのCOMMIT_UNKNOWN解決前はnew attempt allocation 0です。
3. `DELETE_ATTEMPT_INDEX`（phase 2）: remaining attempt=remaining index>=1、fenced=1だけがlegalです。ATTEMPT_ID_INDEXをkey順に選び、そのindexが指すlocal ATTEMPTとexact pair closureで同じbounded witnessからeraseし、消したpair数だけ両remaining countをchecked減算、batch generationを+1します。Pairを別batchへ分割せず、indexだけ/ATTEMPTだけのnew truthを作りません。両countが0になった同じcommitでphase 3へ進み、fenced=1をFINALIZEまで維持します。
4. `FINALIZE`（phase 3）: fresh snapshotでATTEMPT/ATTEMPT_ID_INDEXがともに0、plan remainingがともに0であることを証明します。残るbounded child（EVIDENCE最大9、MANAGEMENT最大9、RETRY_SUMMARY最大5、owner payload BLOB最大2、REVERSE_REPLY最大4と各reply BLOB最大2でreply系最大12、CANCEL_STATE最大1）、primary、STATE/RESULT spine、sequence/idempotency/event map、RESERVATION、RETENTION_BASIS、SCHEDULER_OWNER、CLEANUP_PLANを全て同じgroupでeraseし、service quota/resource capacity/cursorをreleaseします。Initial index countが1以上のplanはATTEMPT_REUSE_FENCE countを-1し、0ならeraseします。Fixed child + spine/shared metadata + distinct ACTIVE predecessorはchecked 64以下です。Commit OK/authoritative committed後だけtransaction/attempt/idempotency/logical-delivery identityを再利用可能にします。

各batch COMMIT_UNKNOWNはplanのold/new batch generation、remaining count、manifest、member presenceでall-old/all-newへ収束し、same batchをblind retryしません。Recovery scanは全phaseで`observed ATTEMPT = remaining_attempt_count`かつ`observed index = remaining_attempt_index_count`を要求します。Phase 1はattempt>=indexで全index backlink present、phase 2はattempt=index>=1かつ全ATTEMPT/INDEXがexact pair、phase 3は両方0です。Initial count変更、remaining増加/不一致、orphan pair、Evidence/BLOB/management/retry/reply/spine/resource proofのearly欠損、fence countとphase-2/3 fenced plan数不一致、cleanup generation変更、batch generation gap/overflow、planなしpartial graphはcorruptです。Capacity `used/reserved`はFINALIZEまで保持するため途中crashで過少申告しません。Cleanupはdurable scan cursorを保存せず、各batchが先頭から再scanして次のlexicographic eligible rowを選びます。RETIRED witness physical cleanupは10.2の別非semantic incremental cleanupです。

## 12. Four-counter validation

1. Retained transaction sequence、ordered-input sequence、owner sequenceはnon-zeroで対応counter以下
2. Sequence/index keyはunique、primary/backlink exact
3. Retention gapを許すためobserved maximumとcounterの一致は要求しない
4. Observed value > counter、zero sequence、duplicate/reuse、wrapはcorrupt
5. `last_visited_owner <= last_assigned_owner`。Visitedがcleanup済みownerを指すことはvalid
6. Counter exhausted marker 1は12章Type 3 invariantに従い、healthはcounter recordから直接再構成

## 13. Resource contribution table

Scanは全live `RESERVATION`の`RESOURCE_VECTOR`をchecked加算し、11 kindのused/reservedを再構成します。これがportable ledgerの唯一の加算元です。Storage logical bytesではありません。下表のdomain truthは各owner reservationが持つべき値のcross-checkであり、同じunitを二重加算しません。

Precommitのadmission/registration/receive-copy checkはunpublished write-transaction stagingで、recovery可能なdurable `reserved`ではありません。PrimaryとRESERVATIONが同じFULL commitで現れた後のexact owner vectorだけを保存します。Committed owner formulasは次です（`L=max_evidence_per_target`、`M=materialized raw count`、`P=payload bytes`、`r=successful resume count`、`d=discard committed 0/1`）。記載外kindはused/reservedともzeroです。

| Owner | Exact live vector |
| --- | --- |
| SERVICE | SERVICE used 1 |
| TRANSACTION Command | TRANSACTION used 1、TARGET used 1、OUTBOX_BYTES used `P` until payload release、EVIDENCE used `1+M` / reserved `L-M` |
| TRANSACTION Event | TRANSACTION used 1、TARGET used 1、EVENT_SPOOL_COUNT used 1 until release、EVENT_SPOOL_BYTES used `P+r*256+d*512` / reserved `(8-r)*256+(1-d)*512` while live、terminal後used `r*256+d*512` / reserved 0、EVIDENCE used `1+M` / reserved `L-M` |
| INGRESS | INGRESS used 1 |
| DELIVERY | DELIVERY used 1 until result/disposition/reconcile terminal、RESULT_CACHE reserved 1 before token/result then used 1 through retention、EVIDENCE used `1+M` / reserved `L-M`、DEFERRED_TOKEN reserved 1 before callback claim |
| CALLBACK | Active tokenのDEFERRED_TOKEN used 1。作成時にDELIVERYの同kind reservedを0へ移し、complete/timeout/recoveryでusedをrelease |

Owner state transitionは該当primary/state、RESERVATION、family 4 capacity metadataを同じwitness groupへ含めます。Aggregateが偶然一致しても、上表と違うownerへのunit移動はcorruptです。

Reservation quota/grant contributionはTRANSACTION ownerだけnon-zeroです。Command/Eventともtransaction non-terminal中`service_inflight=1`、terminal/retainedは0です。Eventはspool未release中だけ`grant_active_count=1`、`grant_active_bytes=P+2560`、required Receipt/discard後は両方0です。Commandのgrant fieldsと他ownerの3 fieldはzeroです。Scannerはanchorのservice keyへgroupし、SERVICE_QUOTA `active_transaction_count/active_spool_count/active_spool_bytes`とgrant snapshot limitをexact cross-checkします。Historical window admissions/payload bytesはSERVICE_QUOTA自身のwindow truthで、RESERVATIONへ複製しません。

| Resource kind | Reservation `used`のsemantic cross-check | Reservation `reserved`のsemantic cross-check |
| --- | --- | --- |
| SERVICE | committed SERVICE 1 | 0 |
| TRANSACTION | nonterminal/retained anchor 1 | 0 |
| TARGET | committed target 1 | 0 |
| OUTBOX_BYTES | required evidence未達Command manifest `total_length` | 0 |
| DELIVERY | nonterminal DELIVERY 1 | 0 |
| EVENT_SPOOL_COUNT | retained unreleased EVENT_SPOOL 1 | 0 |
| EVENT_SPOOL_BYTES | Event payload + consumed management logical bytes、terminal後used ledger bytes | unused management logical bytesだけ |
| RESULT_CACHE | result/disposition/token tombstone 1 | Delivery admission後callback/result前slot 1 |
| EVIDENCE | summary/materialized raw cell各1 | unused raw fixed cell各1 |
| INGRESS | unreduced ORDERED_INGRESS 1 | 0 |
| DEFERRED_TOKEN | CALLBACK ownerのactive token 1 | DELIVERY ownerのcallback前slot 1 |

同じsemantic unitをprimary/index/chunkから直接加算しません。各reservation vectorを上表のprimary/state/fixed-cell truthへ照合します。BLOB chunk数やStorage byte数はOUTBOX/EVENT bytesへ使わずmanifest `total_length`だけをcross-checkします。Derived used/reservedはfamily 4 metadataとexact一致必須です。`high_water`は履歴なので再計算せず、`used+reserved <= high_water <= limit`を検査します。Limitはprofile derivationとexact一致します。

## 14. Durable health reconstruction

Aggregate health recordは保存しません。Healthはreference countでなくcanonical source IDのsetです。

```text
HEALTH_SOURCE_ID = SHA-256(
  ASCII("NINLIL-DOMAIN-HEALTH-SOURCE-V1") ||
  priority:u8 || source_kind:u16 || source_identity:RAW16)
```

同じsource IDの反復観測は1件、別sourceは同じreasonでも別件です。Current health reasonは存在する最小priorityだけで決まり、scan順やhash iteration順を使いません。Durable sourceだけをStage 5で再構成し、instance-only entropy/Bearer/provider/method causeはrestartへcopyしません。

Private registryはclosedです。`source_kind`: 1 CREATE_STORAGE_FAILURE、2 COMMIT_UNKNOWN、3 DELIVERY_CALLBACK_CONTRACT、4 DELIVERY_APPLICATION_FATAL、5 CLOCK_FENCE、6 FAMILY3_COUNTER、7 FAMILY4_CAPACITY、8 EVENT_COUNTER、9 RETENTION_OVERFLOW、10 DELIVERY_COUNTER、11 INTERNAL_INVARIANT、12 SEND_COUNTER。`timer_kind`: 1 ATTEMPT_RECEIPT、2 CANCEL_TIMEOUT、3 TRANSACTION_DEADLINE、4 TRANSACTION_RETRY、5 RESULT_TOKEN、6 RESULT_RECONCILE、7 REVERSE_REPLY_RETRY、8 RETENTION_BASIS。`event_counter_kind`: 1 RETRY_CYCLE、2 CUMULATIVE_ATTEMPTS、3 SPOOL_REVISION、4 COMPLETED_CYCLES、5 MANAGEMENT_OPERATIONS。Create `stage`: 1 OPEN、2 BOOTSTRAP、3 DOMAIN_SCAN、4 RECOVERY_MUTATION、5 IDENTITY、6 CLOCK_BASELINE、7 BEARER_OPEN、8 PUBLISH_CLEANUP。Storage `method`: 1 OPEN、2 BEGIN、3 GET、4 ITER_OPEN、5 ITER_NEXT、6 PUT、7 ERASE、8 COMMIT、9 ROLLBACK、10 ITER_CLOSE、11 CLOSE。Unknown numeric valueはcorruptです。

COMMIT_UNKNOWN single/group identityは次で32 bytesへ閉じます。

```text
COMMIT_FENCE_DIGEST = SHA-256(
  ASCII("NINLIL-DOMAIN-COMMIT-FENCE-V1") ||
  fence_kind:u16 || fence_identity:RAW16)
```

`fence_kind`: 1 WITNESS（identity=witness digest 32 bytes）、2 BOOTSTRAP（identity=current root 8 bytes）、3 CLOCK_BASELINE（identity=complete key digest 32 bytes）、4 IDENTITY_ROTATION（identity=family 2 complete key digest 32 bytes）。EVENT_COUNTER source identityは`transaction_complete_key_digest[32] || event_counter_kind:u16`、CLOCK_FENCEは`owner_complete_key_digest[32] || timer_kind:u16 || stored_clock_epoch[16]`をexact RAW16 contentsにします。

| Priority | source_kind | Exact source identity / durable predicate |
| ---: | --- | --- |
| 1 STORAGE_IO | CREATE_STORAGE_FAILURE | create中だけ`stage:u16 || method:u16 || call_ordinal:u32`。Non-zeroならpublish禁止、successful fresh scan後へ持ち越さない |
| 2 STORAGE_COMMIT_UNKNOWN | COMMIT_UNKNOWN | `source_identity`は全variantでexact `COMMIT_FENCE_DIGEST[32]`だけ。Raw witness/key/group digestを直接HEALTH_SOURCE_IDへ入れない。Authoritative all-old/all-newまでpublish禁止 |
| 3 CALLBACK_CONTRACT | DELIVERY_CALLBACK_CONTRACT | RESULT_CACHE complete key digest。RECOVERY_REQUIREDかつreason exact CALLBACK_CONTRACTだけ |
| 4 APPLICATION_FAILED | DELIVERY_APPLICATION_FATAL | RESULT_CACHE complete key digest。RECOVERY_REQUIREDかつreason exact APPLICATION_FAILEDだけ |
| 5 GRANT_PROVIDER_UNAVAILABLE | none | durable sourceなし |
| 6 CLOCK_UNCERTAIN | CLOCK_FENCE | `owner_complete_key_digest[32] || timer_kind:u16 || stored_clock_epoch[16]`。ATTEMPT/CANCEL/STATE/RESULT/REVERSE_REPLY/RETENTION_BASISのnon-zero old-epoch timerごと |
| 7 COUNTER_EXHAUSTED | FAMILY3_COUNTER | family 3 complete key digest |
| 7 COUNTER_EXHAUSTED | FAMILY4_CAPACITY | family 4 complete key digest |
| 7 COUNTER_EXHAUSTED | EVENT_COUNTER | transaction complete key digest + counter kind u16 |
| 7 COUNTER_EXHAUSTED | RETENTION_OVERFLOW | RETENTION_BASIS complete key digest |
| 7 COUNTER_EXHAUSTED | DELIVERY_COUNTER | RESULT_CACHE complete key digest。RECOVERY_REQUIREDかつreason exact COUNTER_EXHAUSTED |
| 7 COUNTER_EXHAUSTED | SEND_COUNTER | ATTEMPTまたはREVERSE_REPLY complete key digest。`send_counter_exhausted=1`のrecordごとexact 1 source |
| 8 OUTCOME_UNKNOWN | INTERNAL_INVARIANT | family 5 marker complete key digest |

同じDeliveryをRESULT_CACHEとbacklinkから発見してもcomplete RESULT_CACHE key由来の1 sourceだけです。Delivery reasonはpriority 3/4のexact片方で、family 5へ複製しません。CLOCK_FENCEはrecord keyとtimer kindが同じ場合だけdedupし、別timerをまとめません。Source clearはそのcanonical predicateを解消したcommitだけが行い、類似ownerの成功で一括clearしません。Capacity blocked、ordinary capacity exhaustion rejection、Event PARKED_RETRY、business OUTCOME_UNKNOWN、Bearer WOULD_BLOCKはhealth sourceではありません。Priority 3〜8はDEGRADED publish可能、1/2は不可です。

## 15. Stage 5 recovery scan

Scanは1 READ_ONLY snapshotに0-byte prefix iteratorを開き、Storage namespace全体をunsigned-byte lexicographic順で行います。Current rootだけのprefix scanは禁止です。

1. provider schema/open fencing完了
2. family 1〜4 completeness/CRC/current version
3. profile exact compare。Mismatchなら`UNSUPPORTED`でdomain decode/mutation 0
4. exact profileだけfamily 5/6全key、envelope、4096-byte上限、duplicate/order検査
5. witness header/chunk/member old/new検査
6. primary/index/backlink/blob参照検査
7. 4 counter upper bound/unique/orphan検査
8. service quota、ingress/owner、attempt/delivery/result/event ledger検査
9. 11 capacity checked再計算とfamily 4比較
10. durable health source再構成
11. iterator close→READ_ONLY rollback OK後だけresult採用

必要なrecovery mutationはsnapshot終了後、1 item / 1 specific FULL transactionで行い、fresh READ_ONLY scanを先頭から再実行します。Durable scan cursorは作りません。Crash/reopenは常に先頭からです。Identity比較/rotationは最終scan成功後だけです。

Cross-referenceは同じsnapshotのexact `get`を使います。全ID集合をRAMへ保持しません。Private scannerはcaller-owned 255-byte key + 4096-byte value workspaceと`begin/advance(row_budget)/finalize/abort`状態機械にし、関数stackにrecord bufferを置きません。Recognizable futureの唯一のpredicateはsection 5のkey length/prefix/versionとcomplete NLR1 length/CRC条件で、本節の実装はそれを再定義・緩和しません。Predicate外のcurrent root外rowはcorruptです。Futureを読むための65,536-byte allocationは行いません。

## 16. Status precedence

Port call/shapeのearlier primary failureは14章closed mappingを維持します。Precedenceはphase境界ごとにclosedです。

1. family 1〜4 current key/value CRC/shape/length/completeness failure → `NINLIL_E_STORAGE_CORRUPT`
2. family 1〜4 integrity後のprofile mismatch/future profile → `NINLIL_E_UNSUPPORTED`。ここでdomain decode/mutationを行わない
3. Exact profileでのcurrent domain CRC/shape/length、partial group、orphan、duplicate/order、digest/revision、counter/capacity不一致 → `NINLIL_E_STORAGE_CORRUPT`
4. Exact profileかつcurrent domain corruption 0でrecognizable future root/record versionだけ → `NINLIL_E_UNSUPPORTED`

Exact profile domain scan内でfutureとcurrent malformedが混在すればcorruptです。Current rootのunknown subtypeをfutureとしてsilent ignoreしません。Global scanのatomic iterator pairが4096 bytesを超えるrowを返した場合はkeyだけを信用せずcorruptです。

## 17. Mandatory D0/D1/D2 vectors

- `DSK1_KEY_CATALOG`: 全subtype exact key golden、unknown kind/subtype/root version
- `DSV1_RECORD_BOUNDARY`: 各body min/max、4096/4097、chunk 3072/3073、trailing/short/CRC
- `DSI1_BACKLINK`: primary/index exact、missing、orphan、collision raw mismatch、revision conflict
- `DSW1_ALL_OLD_NEW`: create/replace/erase、1/8/9/199/256 members、1/2/25/32 chunks、all-old/all-new/mixed/partial
- `DSW2_SUPERSEDE_CHAIN`: W1 ACTIVE / W2 absent、W1 SUPERSEDED / W2 ACTIVE、複数predecessor、successor欠損、head advance crash境界
- `DSW3_RETIRE_CLEANUP`: SUPERSEDED→RETIRED unknown両truth、semantic head/incoming successor参照、oldest-first chunk partial cleanup、ACTIVE partial拒否
- `DSC1_COUNTERS`: gap、retained max以下/超過、zero/duplicate/wrap、visited cleanup gap
- `DSC2_CAPACITY`: 11 kind used/reserved exact、overflow、double count、manifest/chunk accounting、high-water
- `DSH1_HEALTH`: priority 1..8 source、重複count 0、publish gate
- `DSR1_SCAN`: row budget 1/64、restart先頭、same snapshot get、rollback failure、corrupt>future precedence
- `DSR2_ESP_BOUND`: workspace static upper bound、VLA/recursion/stack record 0、4096 scratch、65,536 allocation 0
- `DSD1_LOGICAL_DELIVERY`: APPLICATION_FIRST、CANCEL_FIRST、later matching APPLICATION、binding conflict、same logical delivery/different attempt、reply-kind single key replacement
- `DSC3_CLEANUP_PHASES`: remote ATTEMPT phase 1、local ATTEMPT+INDEX pair phase 2、fence join/leave/recreate、phase COMMIT_UNKNOWN all-old/all-new、cleanup中submission/ingress WOULD_BLOCK
- `DSH2_HEALTH_GOLDEN`: source/stage/method/timer/counter/fence numeric registry、exact HEALTH_SOURCE_ID/COMMIT_FENCE_DIGEST、Delivery counter exhaustion dedup
- `DSO1_OPERATION_BUILDERS`: kind 1..21全variantのsubject ID、retention kind/key、allowed role、HEAD companion、predecessor、member ceiling、named-hook mapping
- `DSO2_AUTOMATIC_TRANSITIONS`: ATTEMPT/REVERSE_REPLY kind 6 send operation generation、TxGate no-send反復、Bearer-return count、reply BLOB close、SEND_COUNTER MAX、Command timeout/evidence-close/deadline-terminal、Event timeout/park/availability resume kind 14 phase/identity、explicit resume kind 15分離

D0 completionは本章と12/13/14/16のmirror矛盾0です。D1 completionはPort call 0のkey/record/witness pure codecと全golden、D2 completionはmutation 0のbounded scannerです。これらを通るまでStage 5全体、public Runtime、SQLite recoveryを完成扱いしません。

D1は上記case名だけで完了扱いせず、`spec/vectors/domain-store-v1.json`をmachine-readable正本として追加します。各caseはinput semantic fields、expected complete key/value hex、全SHA-256/CRC、expected status、required workspace bytesを持ち、production codecとは独立したvector generatorとのbyte equalityをCI gateにします。D0はformat contract、実hex oracleの追加はD1 deliverableです。
