# 34. R7 T1c Authenticated Hop Fresh-Install Owner

状態: **Proposed — docs-only（implementation / acceptance pending）**  
ADR: [ADR-0014](adr/0014-r7-t1c-authenticated-hop-fresh-install-owner.md)（Proposed）  
前提: [30章](30-r6-secure-radio-wire.md) の Accepted R6 wire freeze、
[31章](31-r7-crypto-provider-and-aead.md) の Accepted T0、
[32章](32-r7-t1-nrw1-single-wire-codec.md) の Accepted T1、
[33章](33-r7-t1b-context-binding-hkdf.md) の Accepted T1b、
および private N6 host candidate（`src/radio/n6_*`）

本章は、**M4 が mint した authenticated Hop install token** を one-shot consume し、
T1b verified Hop binding / key schedule と既存 N6 Hop fresh durable install
（DATA+ACK+N6AL+N6HW の 4-key FULL）を **fail-closed に接続する stateful private owner** を
R7 T1c として定義する。

**Hop 一方向 context の fresh install だけ**を対象とする。E2E install、same-context resume、
M5、W1/L1、counter burn/replay/AEAD 利用、LINK/FRAG/CELL/HA、public ABI 変更は **含まない**。

**SEMANTIC: R7_T1C_HOP_FRESH_INSTALL_OWNER_ONLY**  
**SEMANTIC: R7_T1C_NO_E2E_NO_RESUME_NO_M5**  
**SEMANTIC: R7_T1C_REQUIRES_N6_BOUND_BOOTED_OR_READY**  
**SEMANTIC: R7_T1C_NO_LOCAL_IDENTITY_ABI_CHANGE**  
**SEMANTIC: R7_T1C_ACCEPTED_AUTHORITY_STAMP_ADAPTER**  
**SEMANTIC: R7_T1C_ONE_ACCEPTED_STAMP_PER_DURABLE_INSTALL_ATTEMPT**  
**SEMANTIC: R7_T1C_M4_HOP_TOKEN_ONE_SHOT_CONSUME**  
**SEMANTIC: R7_T1C_CLAIM_COPY_OWNED_NO_CALLER_SPANS**  
**SEMANTIC: R7_T1C_NODE_ID_KDF_CLOSED_MAPPING**  
**SEMANTIC: R7_T1C_SOLE_ACCEPTED_INSTALL_OWNER_API**  
**SEMANTIC: R7_T1C_EXISTING_INSTALL_HOP_NOT_GENERALIZED**  
**SEMANTIC: R7_T1C_FULL_OK_BEFORE_HANDLE_PUBLISH**  
**SEMANTIC: R7_T1C_TOKEN_TERMINAL_ON_CONSUME_START**  
**SEMANTIC: R7_T1C_CU_ALL_PROPOSED_DORMANT_NO_REINJECT**  
**SEMANTIC: R7_T1C_PUBLIC_ABI_UNCHANGED**  
**SEMANTIC: R7_T1C_DOCS_ONLY_PROPOSED_NO_IMPLEMENTATION_CLAIM**

## 1. Boundary and dependency direction

依存方向は次の exact graph とする。

```text
M4 authenticated Hop install mint (incomplete token owner; out of T1c body)
    -> R7 T1c private Hop fresh-install owner
        -> T1c-A accepted authority stamp binder (opaque R2 class-D copy-in)
        -> T1c-B token one-shot consume + copy-owned claim
        -> T1b verified Hop derive (expected digest required)
        -> existing N6 Hop fresh 4-key FULL install engine
            -> N6 durable codec / storage ops / crypto ops
```

初見読者向けの **informative** な成功/失敗導線は次のとおり（Normative な順序は §7、
回復規則は §10 を正本とする）。

```text
R2 accepted sample -> fresh stamp token -> bind/refresh stamp
M4 authenticated Hop -> fresh install token -> consume + copy-owned claim
    -> local identity/node-id/T1b equality checks
    -> stamp consume -> handle-id burn -> N6 four-key durable FULL
         | FULL_OK       -> publish one nonzero handle
         | definite fail -> no handle; fresh stamp + fresh token if policy permits
         | unknown       -> recover_cu only -> ALL_OLD / ALL_PROPOSED / FENCED
```

T1c production source は private とし、`include/ninlil/`・install include・public library へ
公開しない。実装 layout は次に固定する:

```text
src/radio/r7_t1c_hop_install_owner.h  # token/claim/ops + pure prepare helper
src/radio/r7_t1c_hop_install_owner.c  # consume/validate/T1b/node-id preparation
src/radio/n6_context_store.c           # accepted stamp/install entry + static durable body
```

authority adapter と accepted install entry は N6 opaque state、reentry guard、stamp、
bound local identity、static durable body を直接扱うため `n6_context_store.c` に置く。
新 T1c source は `ninlil_n6_t` の内部へ触れず、caller-supplied T0 provider と N6 crypto ops を
immutable borrow して、copy-owned prepared capsule だけを返す。CMake registration は **新規**
T1c authority 1 file とし、
既存 `cmake/ninlil_nrw1_t1b_ctest.cmake` / R6 N6 source authority / T0/T1 authority を
兼用・改名・再解釈しない。

**docs-only Proposed commit で MUST NOT 変更:**

- `docs/30`〜`docs/33` および ADR-0010〜0013 の **Normative semantics / Accepted status**
- 既存 `ninlil_n6_bind_local_identity_accepted` の exact ABI / sole binder / INIT-only 契約
- 既存 raw `ninlil_n6_bind_authority_stamp` の production fail-closed 契約
  （fixture/test-only 成功経路は `NINLIL_N6_TEST_BUILD` のまま）
- 既存 `ninlil_n6_install_hop` / `install_e2e` を一般 token API へ「昇格」すること
- `include/ninlil/*` public ABI

implementation candidate では `n6_context_store.c` の変更が不可避である。現時点の
`docs/07` / `tools/n6_storage_callsite_gate.py` の `n6_context_store.c` hash は、
ADR-0010 §Normative erratum による **limited temporary withdrawal 中の candidate pin** であり、
Accepted と読み替えてはならない。T1c implementation の同じ受入単位で、次をすべて行う:

1. T1c 変更後の source manifest を docs/07 と gate code で lockstep 更新する。
2. docs/30 §20.3 private closed set と T1c delta を明示更新する。
3. candidate baseline に未完だった GCC13 / N6 full regression / mutation corpus と、T1c gates を通す。
4. fresh independent review で新 hash を直接 re-accept し、withdrawal を解消する。

旧 candidate hash を先に Accepted と偽ることも、新 T1c hashへ無監査で飛ぶことも禁止する。
これは provider 統一ではなく T1c の限定的 N6 source re-acceptance である。

## 2. Closed scope and non-claims

### 2.1 含む（T1c Proposed scope）

1. **T1c-A:** R2 accepted class-D snapshot からのみ stamp を copy-in できる
   opaque accepted-authority token / ops / sole production binder
2. **T1c-B:** M4 が mint する authenticated Hop install **incomplete token**、
   別 ops の one-shot consume、固定容量 **copy-owned claim**
3. sole production owner API（`*_accepted` 形）による Hop fresh install 接続
4. claim validation、node-id KDF、local/peer closed mapping、bound local identity 一致
5. T1b verified Hop derive（expected digest 必須）→ private N6 capsule 組立 →
   既存 N6 Hop fresh 4-key FULL → **FULL_OK だけ** handle publish
6. ownership / zeroization / alias / reentry / failure mutation zero /
   heap·VLA·stack / storage call sequence / handle lifetime / state·CU matrix の exact 定義
7. independent oracle / vector / fault / mutation / CTest / package / public ABI /
   GCC13 `-O2` stack / ESP final-ELF / ESP32-S3 target-executed crypto equality KAT gates の **定義**
   （**artifact・実装・JSON が存在するとは主張しない**）

### 2.2 含まない（non-claims; exact）

- E2E fresh install、E2E binding / E2E capsule / E2E token
- same-context resume、M5 floor proof、secret re-inject after DORMANT
- M4 handshake parser / Attachment wire / Join complete
- W1/L1 orchestration、STAMP、FRAME_READY、R1 issue pipeline
- counter allocate/burn、nonce、AEAD Seal/Open、replay admission、TX lease / RX ticket 利用
- T1 composite API、LINK/FRAG/CELL/HA、relay/routing/MAC
- R2 sample producer の **L1 full 実装完成**、R2 production clock full、
   R2 meta への N6 直接書込み
- provider 統一（N6 crypto ops と T0/T1b provider の単一化）
- T1c 以外の N6 semantic/hash-pin 移行（ただし T1c 実装に必要な限定的 source re-pin は
  §1・§12.5 の同一受入単位で必須）
- FIELD/PRODUCTION/Japan legal、RF/USB 実機 HIL、production radio、R7 full
- full `spec/vectors/r7-radio-wire-v1.json` materialization
- **compile/link ≠ HIL**。docs-only Proposed ≠ implementation candidate Accepted

### 2.3 前提状態（N6 lifecycle; exact）

既存 lifecycle / status の Normative anchor は docs/30 §20.3、§20.5、§20.8〜§20.9 と
`src/radio/n6_context_store.h` の private numeric catalog である。T1c が新設する
stamp generation、accepted install owner、install CU kind / pre-state、READY からの追加 install と
ALL_OLD exact restore / ALL_PROPOSED namespace wipe は **本章の delta** であり、既存 N6 の挙動として
先取りしてはならない。implementation acceptance で docs/30 private closed set と source pinへ
同時反映されるまで Proposed のままである。

T1c owner は次を **前提** とし、local-identity bind を再実行・兼用・代替しない。

| precondition | exact |
| --- | --- |
| N6 object | 既に `init` 済み |
| storage + crypto + local identity | すべて bound（`STATE_BOUND` の定義どおり） |
| lifecycle | `boot_scan` 成功後、**`STATE_BOOTED` または `STATE_READY`** |
| authority stamp | T1c-A 成功 bind 済み（§3）; install 直前 prevalidation で確認 |
| stamp freshness | `stamp_generation > last_install_stamp_generation`; 1 accepted stampは最大1 durable install attempt |
| local identity | `ninlil_n6_bind_local_identity_accepted` で bound 済み; **INIT-only 契約を変更しない** |

`STATE_INIT` / `UNINIT` / `DORMANT_DURABLE_NO_SECRET` / `FENCED` / `SHUTDOWN` /
`CU_PENDING` からの T1c install は reject（I/O 0 または token unconsumed — §7）。

## 3. T1c-A — Accepted authority stamp adapter

### 3.1 Problem closed

現行 production `ninlil_n6_bind_authority_stamp` は **必ず fail-closed** する
（R2 accepted-token verifier 未実装; raw stamp field / boolean は trust にならない）。
install は trusted class-D sample（`now_ms` / epoch）を N6HW / N6AL の authority 時刻に使う
（docs/30 §5.3.1.8 / §20.6）。T1c は raw stamp を trust せず、
**R2 が既に class-D として受け入れた opaque token からのみ** copy-in する sole binder を
仕様化する。

**R2 sample producer / L1 full 実装の完成は本 tranche で主張しない。**
本 tranche の受入対象は **adapter 境界**（token/ops/claim/sole binder 契約）である。
既存 raw `bind_authority_stamp` は fixture/test-only 成功 + production fail-closed のまま残す。

### 3.2 Exact private types

local-identity adapter（docs/30 §20.4.1）と同型の incomplete-token パターンを踏襲する。
次の型名・定数値を private ABI v1 として固定する。

```c
/* incomplete; layout private to accepted R2 adapter mint */
typedef struct ninlil_n6_accepted_authority_token
    ninlil_n6_accepted_authority_token_t;

typedef uint32_t ninlil_n6_authority_accept_status_t;
/* OK=0, REJECTED=1, STALE=2, INTERNAL=3 — closed set */

#define NINLIL_N6_AUTH_STAMP_CLAIM_ABI   ((uint16_t)1u)
#define NINLIL_N6_AUTH_STAMP_CLAIM_BYTES ((uint16_t)32u) /* exact; not extensible */
#define NINLIL_N6_AUTH_STAMP_OPS_ABI     ((uint16_t)1u)

typedef struct ninlil_n6_authority_stamp_claim {
    uint16_t abi_version;   /* = 1 */
    uint16_t struct_size;   /* == AUTH_STAMP_CLAIM_BYTES (32) exact */
    uint32_t reserved_zero; /* = 0 */
    uint8_t  clock_epoch_id[16];
    uint64_t now_ms;        /* trusted class-D sample; in-RAM host endian */
} ninlil_n6_authority_stamp_claim_t;

typedef struct ninlil_n6_authority_stamp_ops {
    uint16_t abi_version;   /* = 1 */
    uint16_t struct_size;   /* == sizeof(ops) exact */
    uint32_t reserved_zero; /* = 0 */
    void    *user;
    ninlil_n6_authority_accept_status_t (*consume)(
        void *user,
        ninlil_n6_accepted_authority_token_t *mutable_token,
        ninlil_n6_authority_stamp_claim_t *claim_out);
} ninlil_n6_authority_stamp_ops_t;
```

claim は **copy-owned 固定 32 bytes**。caller pointer span を claim 内に保持しない。
`trusted_class_d` boolean を claim field に置かない — **accept status OK だけが class-D 証明**。
offsetは`abi=0,size=2,reserved=4,epoch=8,now_ms=24`。`sizeof==32`と全offsetを
Host LP64 / ESP ILP32 compile gateでstatic assertする。
accepted refresh が必要なのは、各 fresh install が N6AL/N6HW へその時点の accepted
`now_ms` を書くためである。token の one-shot と N6 stamp の継続 refresh を混同しない。

### 3.3 Sole production binder

```c
ninlil_n6_status_t ninlil_n6_bind_authority_stamp_accepted(
    ninlil_n6_t *n6,
    const ninlil_n6_authority_stamp_ops_t *ops,
    ninlil_n6_accepted_authority_token_t *mutable_token);
```

| rule | exact |
| --- | --- |
| sole production path | production で stamp を bind/refreshする **唯一** の成功経路 |
| raw API | 既存 `ninlil_n6_bind_authority_stamp` は production fail-closed のまま; TEST_BUILD fixture のみ成功可 |
| when allowed | INIT / BOUND / BOOTED / READY。first bind と accepted refresh の両方を許可 |
| refresh | 各呼出しは新しい one-shot token。既 bound 時は epoch byte-exact same かつ `now_ms >= stamp_last_now_ms` のみ成功 |
| epoch change / regression | callback 後 `M4_REQUIRED` + reason `STAMP`、stamp mutation 0。epoch change は shutdown + fresh init が必要 |
| forbidden states | DORMANT ⇒ `INVALID_STATE/STATE`、CU_PENDING ⇒ `COMMIT_UNKNOWN/COMMIT_UNKNOWN`、FENCED ⇒ `FENCED/FENCE`、SHUTDOWN ⇒ `SHUTDOWN/SHUTDOWN`。いずれもcallback 0、token unconsumed |
| preflight | ops/token non-NULL、ops abi/size/reserved、`consume != NULL`; fail ⇒ `INVALID_ARGUMENT/STAMP`、callback 0 |
| alias preflight | `n6` / `ops` fixed-spanはchecked-end + byte-disjoint、opaque tokenとのvisible pointer equalityもcallback前にreject。違反は`ALIAS/ALIAS`、callback 0、token unconsumed |
| opaque spans | token / `ops.user` の完全span non-overlapはtrusted R2 adapter contract。ownerは未知lengthを推測しない |
| reentry | 既存N6 guard下で実行。reentryは`BUSY_REENTRY/REENTRY`、callback 0、token unconsumed |
| generation exhaustion | internal `stamp_generation==UINT64_MAX` ⇒ `CAPACITY/STAMP`、callback 0、token unconsumed |
| consume once | preflight OK 後 `consume` exact 1; **invocation は結果に関わらず token を terminal 化** |
| claim shape | OK + abi=1 + size=32 exact + reserved=0 + epoch not-all-zero |
| success | claimをcopy-ownし、`trusted_class_d`を内部で1、`stamp_bound=1`、last-now更新、nonzero `stamp_generation`をexact +1 |
| non-accept | REJECTED/STALE/INTERNAL/unknown/bad shape ⇒ `M4_REQUIRED` + reason `STAMP`、mutation 0 |
| success status | `OK/NONE`; storage I/O 0 |
| raw boolean trust | claim / stamp raw field 単独で trust を確立してはならない |
| init/shutdown | `stamp_generation` / `last_install_stamp_generation` / stamp copyをzero; generation再利用はfresh object内だけ |

`stamp_generation` と `last_install_stamp_generation` は **T1c が新設する N6 private internal
state** であり、現行 Accepted/candidate source に既存フィールドがあるとは主張しない。

claim bufferはconsume前に全32 bytes zero、callback後はstatus/shape/successを問わず全32 bytesを
secure-zeroする。token / `ops.user` のopaque spanはtrusted R2 adapter contractとしてN6 object/
ops/claimとdisjointを保証し、ownerは未知lengthを推測してpartial-alias検査しない。
R2 adapterは「まだ他のT1c stamp acceptanceに使っていないfresh class-D sample」からだけtokenを
mintする。同じaccepted snapshotからtokenを複製して複数bindすることは禁止する。

### 3.4 Fixture / test

authority fixture mint は **`tests/support/` TEST_ONLY**。production archive に fixture 記号を
出さない。既存 raw stamp fixture 経路は N6 TEST_BUILD のまま残してよいが、
T1c production 受入は `*_accepted` 経路を必須とする。

## 4. T1c-B — Authenticated Hop install token and claim

### 4.1 Incomplete token

```c
typedef struct ninlil_r7_t1c_hop_install_token
    ninlil_r7_t1c_hop_install_token_t; /* incomplete; M4 mint のみが完全型を知る */
```

- token は **M4 等の真正性 owner が mint** する incomplete object。
- T1c / N6 / W1 は token layout を知ってはならない（opaque）。
- token field に **raw `node_id16` を置かない**（§5 で KDF 導出）。
- token に caller pointer span / external buffer を残す設計を禁止する（consume が copy-own）。

### 4.2 Consume ops and status

```c
typedef uint32_t ninlil_r7_t1c_hop_accept_status_t;
#define NINLIL_R7_T1C_HOP_ACCEPT_OK       ((uint32_t)0u)
#define NINLIL_R7_T1C_HOP_ACCEPT_REJECTED ((uint32_t)1u)
#define NINLIL_R7_T1C_HOP_ACCEPT_STALE    ((uint32_t)2u)
#define NINLIL_R7_T1C_HOP_ACCEPT_INTERNAL ((uint32_t)3u)

#define NINLIL_R7_T1C_HOP_CLAIM_ABI   ((uint16_t)1u)
#define NINLIL_R7_T1C_HOP_CLAIM_BYTES ((uint16_t)272u) /* exact */
#define NINLIL_R7_T1C_HOP_OPS_ABI     ((uint16_t)1u)

typedef struct ninlil_r7_t1c_hop_install_claim
    ninlil_r7_t1c_hop_install_claim_t;

typedef struct ninlil_r7_t1c_hop_install_ops {
    uint16_t abi_version;   /* = 1 */
    uint16_t struct_size;   /* == sizeof(ops) exact */
    uint32_t reserved_zero; /* = 0 */
    void    *user;
    ninlil_r7_t1c_hop_accept_status_t (*consume)(
        void *user,
        ninlil_r7_t1c_hop_install_token_t *mutable_token,
        ninlil_r7_t1c_hop_install_claim_t *claim_out);
} ninlil_r7_t1c_hop_install_ops_t;
```

### 4.3 Copy-owned claim（Hop binding 全情報; no caller spans）

claim は T1b Hop binding の全情報を **固定容量配列 + length** で保持する。
`ninlil_r7_binding_bytes` のような caller pointer を claim 内に **保持しない**。

```c
#define NINLIL_R7_T1C_SITE_MAX   ((uint16_t)16u)
#define NINLIL_R7_T1C_ID_MAX     ((uint16_t)32u)

struct ninlil_r7_t1c_hop_install_claim {
    uint16_t abi_version;      /* = 1 */
    uint16_t struct_size;      /* == NINLIL_R7_T1C_HOP_CLAIM_BYTES exact */
    uint32_t reserved_zero;    /* = 0 */

    /* T1b Hop binding material (copy-owned) */
    uint8_t  environment_code; /* LAB=1, FIELD=2 */
    uint8_t  direction_code;   /* IR=0, RI=1 */
    uint8_t  alloc_side;       /* INBOUND_RX=1, OUTBOUND_TX=2 */
    uint8_t  reserved1;        /* = 0 */

    uint16_t site_domain_len;             /* 1..16 (FIELD exact 16) */
    uint16_t attachment_id_len;           /* 1..32 */
    uint16_t initiator_stable_id_len;     /* 1..32 */
    uint16_t responder_stable_id_len;     /* 1..32 */
    uint16_t controller_authority_id_len; /* 0 or 1..32 per T1b matrix */
    uint16_t reserved2;                   /* = 0 */

    uint8_t  site_domain[16];
    uint8_t  attachment_id[32];
    uint8_t  initiator_stable_id[32];
    uint8_t  responder_stable_id[32];
    uint8_t  controller_authority_id[32];

    uint64_t membership_epoch;   /* >0 */
    uint64_t attachment_epoch;   /* >0 */
    uint64_t controller_term;    /* 0 iff authority_len==0 (LAB no-controller) */
    uint32_t hop_context_id;     /* 1..UINT32_MAX-1 */
    uint32_t reserved3;          /* = 0 */

    uint8_t  expected_digest32[32];  /* M4-authenticated; not recomputed as expected */
    uint8_t  traffic_secret32[32];   /* M4-authenticated; copy-owned */
    uint64_t key_generation;         /* 1..UINT64_MAX */
};
```

**固定バイト数:** v1 は自然 align で exact **272 bytes**。offset は
`abi=0,size=2,reserved0=4,environment=8,direction=9,alloc_side=10,reserved1=11,
site_len=12,attachment_len=14,initiator_len=16,responder_len=18,authority_len=20,
reserved2=22,site=24,attachment=40,initiator=72,responder=104,authority=136,
membership_epoch=168,attachment_epoch=176,controller_term=184,context_id=192,
reserved3=196,expected_digest=200,traffic_secret=232,key_generation=264`。
private header は `sizeof==272` と全 `offsetof` を `_Static_assert` し、Host LP64 と ESP ILP32 の
compile gate で pin する。packing pragma/attribute に依存しない。

**claim に置かないもの:**

- raw `local_node_id` / `receiver_node_id` / 任意 node_id field
- caller `const uint8_t *` span
- E2E fields、resume floor、counter、AEAD key/IV 完成形
- M4 wire bytes 全体の opaque blob を「検証なしで通過」する path

### 4.4 Claim validation（owner 側; exact domains）

consume 成功後、owner は T1b Hop matrix（docs/33 §3）と整合する validation を行う。
優先順位は §7。失敗時は claim 内 secret を zeroize し、N6 durable mutation 0。

| field | domain |
| --- | --- |
| environment | LAB=1 / FIELD=2 only |
| direction | IR=0 / RI=1 only |
| alloc_side | INBOUND_RX=1 / OUTBOUND_TX=2 only |
| site_domain_len | FIELD: exact 16 not-all-zero; LAB: 1..16 |
| attachment / initiator / responder lens | each 1..32 |
| controller authority | FIELD: 1..32 + term>0; LAB controller: 1..32 + term>0; LAB no-controller: len=0 + term=0 |
| epochs | membership/attachment >0; controller_term は上表 |
| hop_context_id | 1..UINT32_MAX-1 |
| key_generation | 1..UINT64_MAX |
| expected_digest / traffic_secret | exact 32 bytes。T1c admission hardening として all-zero secret は reject（T1b pure API の一般 domain は変更しない） |
| unused fixed-array tails / reserved | length 後の全 tail byte と全 reserved は exact zero |

claim buffer は consume 前に全272 bytes zero、consume/validation/prepare後は success/failureを問わず
全272 bytesを secure-zeroする。M4 adapter は使用長だけを書き、unused tailへ情報を残さない。

owner が untrusted claim から `digest_hop_binding` を計算し、その結果を expected として
折り返すことは **禁止**（docs/33 §7 と同趣旨）。expected は **M4 token 由来のみ**。

### 4.5 R2 / M4 adapter obligations（Normative checklist）

adapter 実装者が散在する制約を取りこぼさないため、境界義務を次に集約する。詳細値は
§3.2〜§3.3 / §4.1〜§4.4 / §8.3 が正本であり、この表で緩和しない。

| adapter | mint source | one-shot / copy | shape / alias |
| --- | --- | --- | --- |
| R2 authority stamp | まだ別の T1c acceptance に使っていない accepted class-D sampleだけ | bindごとにfresh token。snapshot/token複製禁止 | claim 32 bytes exact、reserved zero、opaque full span disjointをadapterが保証 |
| M4 Hop install | authenticated M4 Hop handshake結果だけ | installごとにfresh token。claimは全可変入力とsecretをcopy-ownし、caller spanを残さない | claim 272 bytes exact、全reserved/unused tail zero、opaque full span disjointをadapterが保証 |

両adapterとも callback return後に token/user spanを ownerへ保持させず、unknown status/shapeを
成功へ縮退しない。token consume invocation開始後は結果に関係なくterminalである。

## 5. Node-id KDF and local/peer closed mapping

### 5.1 Canonical node id（R6 §5.3.0; 変更なし）

```text
node_id16 = SHA-256(
    ASCII("NINLIL-R6-NODE-ID-v1") || u16be(stable_id_len) || stable_id_bytes
)[0..16)
```

実装は既存 `ninlil_n6_node_id16_from_stable`（bound N6 crypto ops）を使う。
T1c が独自 SHA を再実装してはならない。stable_id_len 0 または >32 は reject。

### 5.2 Closed mapping table（direction × alloc_side）

local / receiver は **direction + alloc_side** から closed table で決める。
raw node_id を token/claim field にしない。

| direction | alloc_side | local role | `local_node_id` from stable | `receiver_node_id` from stable |
| --- | --- | --- | --- | --- |
| IR `0` | OUTBOUND_TX `2` | initiator = sender | initiator | responder |
| IR `0` | INBOUND_RX `1` | responder = receiver | responder | responder |
| RI `1` | OUTBOUND_TX `2` | responder = sender | responder | initiator |
| RI `1` | INBOUND_RX `1` | initiator = receiver | initiator | initiator |

意味:

- **receiver_node_id** = 当該 N6AL の inbound context id を allocate する node
  （INBOUND では常に local; OUTBOUND では peer）
- **local_node_id** = 本デバイス。bound local identity と **byte-exact 一致必須**
- 不一致 ⇒ install reject、durable mutation 0、reason `LOCAL_IDENTITY`

導出順序: claim validation OK → initiator/responder から 2× `node_id16_from_stable` →
table 適用 → local match → 以降 capsule へ copy。
2回のnode-id KDFのいずれかが、shape-validなbound N6 crypto callbackの実行失敗により
失敗した場合は `CRYPTO/CRYPTO`。prepared/capsule/handleは非公開、durable I/O 0、
tokenはconsume済みのためterminalとする。これはT1b verified derive失敗と独立した
status-map rowおよびfault-injection gateとする。

## 6. Sole install owner API

### 6.1 Exact private signature

```c
ninlil_n6_status_t ninlil_n6_install_hop_accepted(
    ninlil_n6_t *n6,
    const ninlil_r7_crypto_provider *t0_provider,
    const ninlil_r7_t1c_hop_install_ops_t *ops,
    ninlil_r7_t1c_hop_install_token_t *mutable_token,
    ninlil_n6_handle_t *out_handle);
```

| rule | exact |
| --- | --- |
| sole production Hop fresh install path | production で Hop fresh を成功させる **唯一** の owner API |
| 既存 raw install | engineはproduction compileされるがraw M4はfail-closed、成功はTEST_BUILD fixtureのみ; 一般 token 化しない |
| E2E | 本 API に E2E を混ぜない; E2E は別 tranche |
| public ABI | `include/ninlil` 変更 0 |
| T0 provider | caller-owned immutable borrow for call lifetime only; exact T0 ABI validation は token consume 前 |
| trusted caller | L1/platform private ownerだけがHost OpenSSL/ESP mbedTLSのAccepted factory出力を渡す。任意caller-built callback tableは禁止 |
| out_handle | valid non-NULL + disjoint確認後に0初期化; successのみnonzero publish。NULL/ALIAS pathはbyte-unchanged |

ここで **Accepted T0 factory output** は exact に次の private factory が成功時に一括 publishした
`ninlil_r7_crypto_provider` だけを指す。

- Host: `src/radio/r7_crypto_openssl3.h` の
  `ninlil_r7_crypto_openssl3_provider_init`
- ESP-IDF: `ports/esp-idf/src/r7_crypto_mbedtls.h` の
  `ninlil_r7_crypto_mbedtls_provider_init`

T1c production callsite gate は platformごとの上記 factory → accepted owner の記号/呼出し集合を
exact-setで固定する。caller-built callback table禁止は **T1c accepted-install境界固有**であり、
docs/31 の汎用private T0 ABIや既存T0 testsのfixture構築契約を変更しない。

### 6.2 Exact private prepared output / helper

prepare helperのcopy-owned出力はraw provenance fieldを持たないexact **120 bytes**:

```c
typedef struct ninlil_r7_t1c_prepared_hop_install {
    uint8_t  layer_code;       /* HOP constant */
    uint8_t  direction_code;
    uint8_t  alloc_side;
    uint8_t  reserved_zero;
    uint32_t context_id;
    uint64_t membership_epoch;
    uint64_t key_generation;
    uint8_t  binding_digest32[32];
    uint8_t  traffic_secret32[32];
    uint8_t  local_node_id[16];
    uint8_t  receiver_node_id[16];
} ninlil_r7_t1c_prepared_hop_install_t;

ninlil_n6_status_t ninlil_r7_t1c_prepare_hop_install(
    const ninlil_r7_crypto_provider *t0_provider,
    const ninlil_n6_crypto_ops_t *bound_n6_crypto,
    const uint8_t bound_local_node_id16[16],
    const ninlil_r7_t1c_hop_install_ops_t *ops,
    ninlil_r7_t1c_hop_install_token_t *mutable_token,
    ninlil_r7_t1c_prepared_hop_install_t *out_prepared,
    ninlil_n6_reason_t *out_reason);
```

offsetは`layer=0,direction=1,alloc_side=2,reserved=3,context=4,membership=8,
key_generation=16,digest=24,secret=56,local=88,receiver=104`、`sizeof==120`。
Host LP64 / ESP ILP32で全offset/sizeをstatic assertする。N6 TUはbound `&n6->crypto`を
call-lifetime immutable borrowでhelperへ渡し、bound local identity 16 bytesも同じguard下でborrowする。
このprivate layoutを全offsetまでpinする理由は、Host/ESPで同一copy-owned capsuleを作ること、
paddingへsecret residueを残さないこと、mutation/oracle gateがfield境界を決定的に検査できることにある。
将来field追加は暗黙ABI拡張ではなく、仕様・assert・oracleを同じtrancheで更新する。
helperはnode-id mapping後・T1b derive前にlocal byte-matchし、N6 entryもprepared返却後に再確認する。
callerがN6 crypto ops/local identityを注入するAPIは作らない。
全known-size span/checked-end/aliasをwrite前に検査する。valid disjoint確認後に`out_prepared`全zero、
`out_reason=NONE`とし、successだけpreparedをpublish、N6 entryがdurable call終了後に全zeroする。
NULL/overflow/ALIAS pathは両output byte-unchanged。`out_reason`はstatusと§11のexact mapに一致する。

このcompile dependencyはT1c bridgeだけの明示的 `T1c -> T1b + N6 crypto contract` である。
Accepted T1b pure TU/headerへN6 dependencyを逆流させない。

### 6.3 Existing install_hop との関係

T1c owner は **private N6 capsule** を stack 上で組み立て、既存 durable engine の
**内部 4-key FULL 経路**を呼ぶ。採用する compile dependency と ownership は次のとおり:

1. `r7_t1c_hop_install_owner.c` は token consume、claim validation、bound N6 crypto opsによる
   node-id KDF、T1b verified
   derive を行い、copy-owned prepared capsule を返す pure/private helper とする。N6 object/state/
   storage/durable helperへはアクセスしない。
2. `ninlil_n6_install_hop_accepted` 本体は `n6_context_store.c` に置く。N6 reentry guard 下で
   state/stamp/local identity を検証し、prepare helper の成功後だけ static durable body を呼ぶ。
3. `install_hop` の durable body を同じ TU の static helper に抽出し、fixture gate と accepted
   entry の二つからだけ呼ぶ。raw `PROVENANCE_M4_AUTHENTICATED` capsule を受ける外部記号は作らない。
4. `n6_context_store.h` の既存 raw capsuleを T1c header/APIへ公開・再利用しない。

**caller が raw capsule + M4 tag を渡して成功する API を public/private に新設しない。**

## 7. Owner order（exact linearization）

単一 owner 呼出し内の順序は次の **exact** とする。前段 error を後段 status で上書きしない。
§9 equality gate greenはproduction artifactの受入前提であり、runtime linearization stepではない。

```text
I0  n6/provider/ops/token/out 全top-level pointerのNULL preflight、
    n6/out/provider/ops fixed-span checked-end + pairwise alias preflight、
    opaque tokenとknown-spanのvisible pointer equality preflight（write 0）
    NULL/overflow/ALIAS ⇒ caller output/input byte-unchanged、token unconsumed、I/O 0
I1  disjoint valid後だけ *out_handle=0; then N6 object validation; reentry enter; top-level prevalidation
    （token 未消費; storage I/O = 0）
    - state ∈ {BOOTED, READY}
    - stamp_bound == 1
    - stamp_generation > last_install_stamp_generation
    - local_id_bound == 1
    - T0 provider exact ABI valid
    - ops abi/size/reserved, consume != NULL
    - no live CU_PENDING / fence blocking install
    - SHUTDOWNは既存 `n6_enter` の `SHUTDOWN/SHUTDOWN`をそのまま返す
    fail ⇒ token unconsumed, I/O 0, mutation 0
I2  authority stamp bound 再確認（I1 と同一条件; 重複確認可）
I3  token one-shot consume / copy-own claim
    - claim buffer all-zero before consume
    - consume exact 1
    - **consume 開始後、OK / definite fail / COMMIT_UNKNOWN はすべて token terminal**
I4  claim validation（§4.4）
I5  node ids derive + closed mapping + local identity byte match（§5）
I6  build T1b hop_binding_input from claim fixed arrays（spans point into claim copies only）
I7  T1b `ninlil_r7_derive_hop_key_bundle_verified`
    （provider = T0 portable; expected_digest = claim; secret = claim）
    - mismatch / structural / backend fail ⇒ zero claim secrets, I/O 0 after consume, no N6 FULL
I8  private N6 capsule assembly from **same claim**
    - authenticated provenance は accepted entry の control flow で確立（raw field/tag なし）
    - layer = HOP, direction/alloc_side/context_id/epoch/kgen/digest/secret/node ids
I9  existing N6 capacity/RO structural precheck（durable mutation 0）
I10 RO success後、current stamp generationをdurable attemptへconsumeし、
    `last_install_stamp_generation`更新（以後のRW failure/CU/successを問わず次attemptはrefresh必須）
I11 RW begin前にhandle idをnonzero pre-reserve
    （slot + CU pending copyへ保持、未publish; 以後のfailure/CUではburnして再利用しない）
I12 RW begin + N6 Hop fresh 4-key FULL（DATA+ACK+N6AL+N6HW）
I13 FULL_OK only → RAM handle publish + READY; zero residual stack secrets
    rollback-proven definite non-corrupt fail → no handle; zero pending secret; pre-state維持
    CORRUPT/provider-shape/cleanup・rollback failure → no handle; FENCED + namespace secrets wipe
    （いずれもreserved handle idはburn）
    COMMIT_UNKNOWN → handle 0; CU_PENDING; only recover_cu 許可（§10）
```

### 7.1 Validation priority（status mapping sketch）

| order | failure class | token | storage I/O | handle |
| ---: | --- | --- | --- | ---: |
| 0 | top-level NULL / overflow / ALIAS | unconsumed | 0 | **unchanged** |
| 1 | invalid N6 object / shape / reentry / wrong state | unconsumed | 0 | 0 |
| 2 | stamp unbound | unconsumed | 0 | 0 |
| 3 | ops preflight | unconsumed | 0 | 0 |
| 4 | consume non-OK / claim shape | **terminal** | 0 | 0 |
| 5 | claim domain / node map / local mismatch / node-id KDF fail | terminal | 0 | 0 |
| 6 | T1b verified derive fail | terminal | 0 | 0 |
| 7 | N6 capacity / structural precheck | terminal | RO may | 0 |
| 8 | N6 rollback-proven definite non-corrupt fail | terminal | yes | 0 |
| 9 | N6 CORRUPT/provider-shape/cleanup fail | terminal | yes | 0; FENCED |
| 10 | N6 COMMIT_UNKNOWN | terminal | yes | **0** |
| 11 | FULL_OK | terminal | yes | **published** |

### 7.2 T1b input assembly（exact）

claim 固定配列から `ninlil_r7_hop_binding_input` を組む:

| T1b field | claim source |
| --- | --- |
| environment_code | claim.environment_code |
| site_domain | `{claim.site_domain, claim.site_domain_len}` |
| membership_epoch | claim.membership_epoch |
| attachment_id | `{claim.attachment_id, claim.attachment_id_len}` |
| attachment_epoch | claim.attachment_epoch |
| initiator_stable_id | `{claim.initiator_stable_id, claim.initiator_stable_id_len}` |
| responder_stable_id | `{claim.responder_stable_id, claim.responder_stable_id_len}` |
| controller_authority_id | len=0 なら `{NULL,0}`; else array+len |
| controller_term | claim.controller_term |
| hop_context_id | claim.hop_context_id |
| direction_code | claim.direction_code |

pointer は **claim 内 copy のみ**。caller token へ alias してはならない。

### 7.3 Prepared N6 capsule mapping（exact）

| N6 durable input | sole source |
| --- | --- |
| layer_code | constant `HOP` |
| direction_code / alloc_side | validated claim values |
| context_id | `claim.hop_context_id` |
| membership_epoch / key_generation | same-named claim fields |
| binding_digest32 | **byte-exact `claim.expected_digest32`**; only after T1b verified match |
| traffic_secret32 | **byte-exact `claim.traffic_secret32`** |
| local_node_id / receiver_node_id | §5 closed mapping outputs |

prepared capsuleにprovenance fieldを公開しない。accepted N6 entryのcontrol flowそのものが
provenance capabilityであり、raw capsuleへauthenticated tag/booleanを追加する設計は禁止する。

## 8. Ownership, zeroization, alias, reentry, stack

### 8.1 Secret ownership

| material | owner after consume | lifetime |
| --- | --- | --- |
| token | terminal; adapter が invalid 化 | retry 不可; 新 token 必須 |
| claim.traffic_secret32 / digest | owner stack copy | install 終了（OK/fail/CU 入口）まで; 後 zero |
| T1b hop_key_bundle | preparer stack | verified derive成功確認後ただちにzero。runtime N6 leaseにはcopyせず、N6が後続TX/RX時にsame secret/digestからderive |
| N6 slot traffic_secret32 | N6 | FULL_OK 後 live slot; CU ALL_PROPOSED 後は §10 |
| handle | caller | FULL_OK 後のみ usable |
| pre-reserved handle id | N6 internal monotonic counter + pending slot/CU copy | RO success後にburn; FULL前後のfail/CUでも再利用しない。commit後の再allocation禁止 |

### 8.2 Zeroization

- claim / bundle / capsule stack / 一時 IKM は **全 return path** で secure-zero
  （compiler が消去を省略できない private `ninlil_n6_secure_zero`）
- `r7_t1c_hop_install_owner.c` は `n6_crypto_provider.h` が宣言する既存
  `ninlil_n6_secure_zero` を使用し、新しいsecure-zero実装/semanticを増やさない。
  T1bのTU-local helperを外部化したり、Accepted T1b sourceへ逆依存を追加したりしない
- failure 時 **caller の入力 buffer を mutation しない**
  （token は consume により terminal 化する点を除く）
- NULL/checked-end overflow/ALIASはcaller outputsもbyte-unchanged。disjoint valid後のfailure/CUだけ
  `*out_handle=0`を保証する
- zero-fill of caller outputs を「mutation zero」と呼んではならない
- I10より前のfailureはN6 durable/business mutation 0。I10以降のfailureはcurrent stamp generationの
  consume（`last_install_stamp_generation`更新）だけ、I11以降はそれに加えmonotonic internal
  handle id burnを許容する。全failureでhandle publish 0、durable mutationはCOMMIT_UNKNOWN以外0
- ALL_PROPOSED 後の pending secret 破棄は §10

### 8.3 Alias

ownerがサイズを知る `n6` object / provider / ops / out_handle の全spanはpairwise disjoint必須。
partial overlapを**output zeroより前に**checked-`uintptr_t`でrejectし、ALIAS pathは全caller bytes
unchanged。read-only同士でもtyped object span overlapを許容しない。
opaque token の完全 byte span は T1c から知り得ないため、token と n6/provider/ops/out の
**全 byte non-overlap は trusted M4 adapter contract** とし、visible pointer equality は owner が
reject、fixture adapter は canary/overlap matrix で契約を実証する。claim/stack は caller-visible
spanではなくalias検査対象と書いてはならない。`ops.user` / provider `ctx` の完全 spanも各
trusted provider contractに従い、ownerは推測したlengthで検査しない。
T0 providerのABI shape検証だけではcallback provenanceを証明できないため、production source/callsite
gateはaccepted installの全callsiteがplatform private factory出力を使うことをexact-setで検査する。
`TEST_BUILD` では負試験/fault injection用のprivate fixture factoryのみ追加可とするが、
production object / final ELF / installed header / production callsite exact-setへの混入はred。

### 8.4 Reentry

N6 既存 reentry guard 下で owner を実行する。reentry ⇒ `BUSY_REENTRY`、
pre-consume なら token unconsumed、post-consume なら token は既 terminal。

### 8.5 Heap / VLA / stack

- heap / VLA / process-global mutable secret cache 禁止
- portable production owner/preparation helper の GCC Release exact `-O2 -fstack-usage` static
  frame ceiling は各 **`<= 2048` bytes**。既存 N6/T1b ceiling を弱めない
- ESP final-ELF は owner API を実参照（compile/link ≠ HIL）

### 8.6 Storage call sequence

pre-consume failure: open/begin/put/commit **0**。  
post-consume N6 path: docs/30 §5.3.1.8 の RO precheck → 1 multi-key FULL。  
CU: `recover_cu` のみ（§10）。

## 9. Key schedule: T1b bundle vs N6 derive

### 9.1 同一 schedule の正本

R6 §8 / T1b §7 / N6 `ninlil_n6_derive_hop_keys` は次で **同一**である:

```text
salt = hop_context_binding_digest32
ikm  = traffic_secret32
PRK  = HKDF-Extract(salt, ikm)   /* または N6 hkdf_sha256 の同等 Extract+Expand 一括 */
DATA key16 = Expand(PRK, "NINLIL-R6-HOP-DATA-KEY-v1", 16)
DATA iv12  = Expand(PRK, "NINLIL-R6-HOP-DATA-IV-v1", 12)
ACK  key16 = Expand(PRK, "NINLIL-R6-HOP-ACK-KEY-v1", 16)
ACK  iv12  = Expand(PRK, "NINLIL-R6-HOP-ACK-IV-v1", 12)
```

### 9.2 Bundle discard 許可条件（exact gate）

T1b が返した `ninlil_r7_hop_key_bundle` を **捨てて** 既存 N6 derive だけを durable/lease に
使うことは、次を **全て**満たす場合 **だけ** 許可する:

1. same digest = salt、same secret = IKM、same **four** R6 Hop labels の同一 schedule であること
   を正本（本章 + docs/30/33）で固定済み
2. **cross-implementation equality oracle / gate** が、T1c subset の **全 Hop vectors** について
   T1b bundle の DATA/ACK key/IV と、N6 `derive_hop_keys` 出力が **byte-identical** であることを
   証明する
3. 飾りの derive（呼ぶだけ・比較しない・一部 lane だけ）は **禁止**

**採用（固定）:** equality gate を Required とし、runtime の sole path は
N6 `derive_hop_keys`。T1b verified derive は digest 認証 + schedule pin の authority とする。
production artifact は equality gate green の固定 source/vector SHA からだけ配布可能とする。
runtime install が test JSON/gate flagを読み、実行時に分岐する設計は禁止する。

### 9.3 Provider 二重系

T1b は T0 `ninlil_r7_crypto_provider`、N6 は `ninlil_n6_crypto_ops` を使う。
本 tranche は **provider 統一を完成主張しない**。一方、T1c implementation acceptanceでは
`n6_context_store.c` の限定的 source re-pinを§1/§12.5どおり必須とする。
equality gate が両 backend（Host OpenSSL 経由 T0 と N6 host HKDF）の一致を pin する。
T1c は N6 crypto ops から T0 provider を構築しない。Host/ESP owner が Accepted T0 factory で
得た provider を `ninlil_n6_install_hop_accepted` へ明示的に immutable borrow する。

## 10. COMMIT_UNKNOWN and ALL_PROPOSED

| outcome | handle | state | allowed next | secret |
| --- | ---: | --- | --- | --- |
| FULL_OK | published nonzero | READY（または同等 live） | TX/RX 既存 API | live slot 保持 |
| rollback-proven definite non-corrupt fail | **0** | exact pre-install BOOTED/READY | fresh stamp + 新token。same claimはM4 policy/freshnessが再承認した場合だけ可 | pending破棄 |
| CORRUPT / provider-shape / cleanup・rollback fail | **0** | **FENCED** | operator/fence recoveryのみ | namespace secrets zero |
| COMMIT_UNKNOWN | **0** | `CU_PENDING` | **`recover_cu` のみ** | CU plan copy-owned |
| recover ALL_OLD | 0 | exact pre-install state（BOOTED/READY） | 新 token。same claim は M4 policy と current high-water/floor が再承認した場合だけ可 | plan drop |
| recover ALL_PROPOSED | 0 | **`DORMANT_DURABLE_NO_SECRET`** | 自動/in-place T1c復旧なし。M5またはauthoritative retirement/re-provisioning（ともに非範囲）までTX/RX 0; 同 token/secret/context **再注入・再試行禁止** | **全 live/pending secret破棄、全handle/lease/ticket invalid** |
| recover MIXED/THIRD | 0 | FENCED | fence recovery | secrets zero |

**exact:**

- CU 中の install / TX / RX / 他 mutation API は禁止（既存 N6 と整合）
- ALL_PROPOSED は durable が proposed を採用した可能性を意味するが、
  T1c は **handle を publish しない**（docs/30: install CU never publishes a handle）
- 同 token は consume 時点で terminal のため再使用不可
- **ALL_PROPOSED に限り**、同 traffic_secret / 同 key_generation / 同 context の再注入 install は
  禁止（`NO_SAME_KEY_COUNTER_RESET_INSTALL` と整合）。rollback-proven definite non-corrupt fail と ALL_OLD は
  durable non-applyが証明済みなので、同一tokenは不可だが、fresh stamp + 新しいauthenticated
  tokenによる再試行を一律禁止しない。FENCED pathはこのretry規則の対象外
- ALL_PROPOSED後、現行T1cだけで同laneを再利用可能へ戻すAPIはない。運用上はcontextを
  unavailableとして隔離し、後続M5、またはaccepted external proofによるretire/fence/reclaim完了後の
  shutdown + fresh init + fresh provisioningを待つ。既存`reclaim`/`gc`はdocs/30 §20.9どおり
  typed authority/proof必須であり、T1cがraw operator bypassを追加してはならない
- FENCEDも同様に自動retry不可。docs/30 §20.9のauthoritative recovery、または外部で旧contextを
  authoritativeに廃棄した後のfresh object再provisionだけを許し、秘密/handleの復活を推測しない
- T1c実装時に CU planへclosed `install_cu_kind={NONE=0,FIXTURE=1,T1C_ACCEPTED_HOP=2}` と
  `install_pre_state` をcopy-ownし、install kindのALL_OLDはそれをexact復元する。
  現行candidateの無条件BOOTED化はREADYからのmulti-context installを壊すため受入不可
- ALL_PROPOSEDのnamespace-wide DORMANT/wipeは **`install_cu_kind != NONE` のinstall CUだけ**。
  pendingだけでなく既存live slotのsecret/handleと全lease/ticketをsecure-zeroする。
  TX/RX CU（kind=NONE）はAccepted既存post-actionを維持し、このwipeを絶対に実行しない
- `install_cu_kind=T1C_ACCEPTED_HOP` はaccepted entryだけが設定し、fixture/raw callerは設定不可。
  名前だけDORMANTで旧secretをRAMに残す実装は禁止
- recover entryはstorage reopen/read/classify/array postより前にCU plan coherenceを全検証する:
  `kind`はclosed domain、`kind==NONE` iff `pending_install==0`かつINSTALL_HANDLE post 0、
  install kindなら`pending_install==1` + exact one INSTALL_HANDLE post +
  `install_pre_state∈{BOOTED,READY}` + pending reserved handle nonzero。
  T1C kindはさらにpending layer=HOP、`n_keys==4`、DATA/ACK/N6AL/N6HWがeach exact 1、
  全4 entryのcanonical key/value encoding、same pending slot/context/digest/key_generation/namespace/scope、
  exact one INSTALL_HANDLE postの件数と配置を要求する。2-lane subset、N6AL/N6HW欠落、
  lane差替えをALL_OLD/ALL_PROPOSED分類の入力にしてはならない
- coherence不一致はlive CU storage handleをforce-close once（存在時）後、classify get/array post 0、
  `CORRUPT/FENCED` + namespace secrets zero。破損planをTX/RX扱い・install扱いへ推測補正しない
- resume / M5 は本 tranche に **含めない**

### 10.1 Caller / operator next action（informative; Normative mapは§10/§11）

| class | next action |
| --- | --- |
| pre-consume shape/state/alias | caller bugまたは順序を修正。callback未実行ならtokenは保持 |
| stamp stale/unbound、M4 proof/identity failure | 新accepted sample/stampまたは新M4 handshakeからfresh tokenを取得 |
| rollback-proven STORAGE/CAPACITY | backoff/容量是正後、policyが許すfresh stamp + fresh tokenで再試行 |
| COMMIT_UNKNOWN | 他mutationを止め、`recover_cu`だけを再実行してclassification完了を待つ |
| ALL_OLD | durable non-apply確認済み。fresh stamp + fresh tokenで再承認可能 |
| ALL_PROPOSED / DORMANT | T1c内のretry禁止。M5またはauthoritative retirement/re-provisioningへescalate |
| CORRUPT / FENCED | operator介入。typed proofを伴うrecoveryまたはauthoritative disposal + fresh object |
| SHUTDOWN | old objectは再利用せずfresh init |

## 11. Status catalog（owner-visible; private）

owner は既存 `ninlil_n6_status_t` / `reason_t` を再利用する（新 public ABI なし）。
数値と既存意味論の正本は `src/radio/n6_context_store.h` および docs/30 §20.3/§20.5/§20.8〜§20.9。
T1c固有の組合せと優先順位だけを次表で追加し、既存値を再定義しない。

| 状況 | exact status | exact reason |
| --- | --- | --- |
| invalid N6 object | `INVALID_ARGUMENT` | object invalidのためlast_error publishなし |
| NULL provider/ops/token/out | `INVALID_ARGUMENT` | `NULL` |
| fixed-span overflow / alias | `ALIAS` | `ALIAS` |
| ops ABI/shape | `INVALID_ARGUMENT` | `PROVENANCE` |
| T0 provider ABI/shape | `INVALID_ARGUMENT` | `CRYPTO` |
| INIT/BOUND/DORMANT lifecycle | `INVALID_STATE` | `STATE` |
| CU_PENDING | `COMMIT_UNKNOWN` | `COMMIT_UNKNOWN` |
| FENCED | `FENCED` | `FENCE` |
| SHUTDOWN | `SHUTDOWN` | `SHUTDOWN` |
| stamp unbound/already-used generation | `M4_REQUIRED` | `STAMP` |
| reentry | `BUSY_REENTRY` | `REENTRY` |
| token consume non-OK | `M4_REQUIRED` | `PROVENANCE` |
| claim ABI/domain/tail fail | `M4_REQUIRED` | `PROOF` |
| local id mismatch | `M4_REQUIRED` | `LOCAL_IDENTITY` |
| N6 node-id KDF callback failure | `CRYPTO` | `CRYPTO` |
| T1b expected digest mismatch | `M4_REQUIRED` | `PROOF` |
| T1b provider/backend/other non-OK | `CRYPTO` | `CRYPTO` |
| N6 context/lane collision、allocator floor、kgen≤high-water | `INVALID_ARGUMENT` | `DOMAIN` |
| owner/N6/storage capacity | `CAPACITY` | `CAPACITY` |
| storage I/O/BUSY rollback-proven | `STORAGE` | `STORAGE` |
| provider shape/codec/cleanup/rollback fail | `CORRUPT` | `CORRUPT` |
| CU | `COMMIT_UNKNOWN` | `COMMIT_UNKNOWN` |
| success | `OK` | `NONE` |

上表を exact map とし、実装で同じ表を mutation gate へ pin する。
invalid N6 objectおよびI0のNULL/overflow/ALIAS returnは`last_error`をpublishせず、表の
status/reasonはlogical return valueとする（caller bytes unchangedのためN6 objectもmutation 0）。
I1でN6 object validationが成功した後の全returnはcurrent callのstatus/reason/stateで
`last_error`を上書きし、raw engineの古い/stale errorを漏らさない。
この表はinstall owner用。§3.3 authority binderのgeneration exhaustionだけは同API固有の
`CAPACITY/STAMP`であり、install ownerの`CAPACITY/CAPACITY`へ正規化しない。

## 12. Oracle, vectors, and gates（定義のみ; 存在主張なし）

本章は **Proposed docs-only** である。次の artifact 名は受入時の **予定 authority** であり、
リポジトリに JSON/実装が存在するとは主張しない。

### 12.1 Planned artifact names

```text
tools/r7_t1c_hop_install_oracle.py
spec/vectors/r7-t1c-hop-install-subset.json
tests/radio/private/r7_t1c_hop_install_vectors.h
cmake/ninlil_nrw1_t1c_ctest.cmake
```

### 12.2 Planned positive vector set（ID/count exact）

committed oracle positive install setはexact **24 vectors**:

```text
environment_class ∈ {FIELD, LAB_CONTROLLER, LAB_NO_CONTROLLER}
direction         ∈ {IR, RI}
alloc_side        ∈ {INBOUND_RX, OUTBOUND_TX}
boundary          ∈ {MIN, MAX}
3 * 2 * 2 * 2 = 24
ID = R7-T1C-HOP-<ENV>-<DIR>-<SIDE>-<BOUNDARY>  /* uppercase closed tokens */
```

`DIR={IR,RI}` は docs/33 のcanonical direction tokenをそのまま使う。T1bの `D0/D1` suffixを
流用せず、IDだけでdomain値を読めるようにする。bridge/oracleは旧 `T1C-HOP-*` をrejectする。

MIN/MAXはdocs/33 domainの全可変length/numeric boundaryを組で覆い、全vectorの
expected digest/traffic secret/context/kgenは重複しない。bridgeはID exact-set/count=24を要求する。
これに加え、READYからの2件目install、stamp equal-now refresh/advancing refresh、CU recoveryは
state/fault testsで覆い、24-vector oracle countへ水増ししない。

- FIELD / LAB-controller / LAB-no-controller
- IR/RI × INBOUND/OUTBOUND
- T1b digest match + N6 FULL_OK happy path（host fixture storage）
- equality: T1b bundle ≡ N6 derive（全 Hop positive）
- node-id: initiator/responder stable ID → N6 node_id16 がindependent oracleとbyte-identical
- Host: OpenSSL T0 + N6 host deriveを全positive vectorで実行
- ESP32-S3 target: mbedTLS T0 + packaged N6 deriveを同じ全positive vectorで実行し、
  exact count + aggregate digestをhost oracleと一致

### 12.3 Planned negative / fault set

- prevalidation: NULL、wrong state、stamp unbound、token unconsumed 証明
- ops ABI under/over size、consume REJECTED/STALE/INTERNAL
- claim domain: env/dir/side、epoch 0、context 0/MAX、kgen 0、all-zero secret
- node map: local mismatch、stable len 0/>32、Host/ESPでbound N6 SHA callback失敗を注入し
  `CRYPTO/CRYPTO`、prepared/handle非公開、durable I/O 0をexact検査
- T1b: expected digest 1-bit flip ⇒ mismatch
- secret sensitivity: authenticated fresh secret 1-bit変更はvalidで、T1b/N6双方が同じ別bundleを出し
  baseline bundleとは不一致。未認証token byte tamperはM4 adapterがconsume REJECTEDでclaim publish 0
- alias / reentry / double consume
- N6: capacity、lane collision、kgen ≤ high-water、CU classes
- ALL_PROPOSED 後の same-secret re-inject 禁止
- package: tests-OFF で production object exact once、install/public leakage 0
- production callsite exact-set: accepted Host/ESP factory以外のT0 provider construction/injectionをred。
  TEST_BUILD private fixture factoryは負試験だけに許可し、production object/final ELF/installには0
- public ABI: `include/ninlil` 無変更
- GCC13 exact `-O2 -fstack-usage` owner/preparer 各 ≤2048; N6/T1b 既存 ceiling 非弱体化
- ESP-IDF v5.5.3 component source once + final ELF 実参照
- `ports/esp-idf/hil_app` target-executed T1c crypto KAT: 全Hop positive equality、exact vector count/
  aggregate digest、firmware source SHA/ESP-IDF versionをmachine-readable evidenceへ固定
- fixture 記号が production nm に出ないこと

### 12.4 Planned CTest prefix

`nrw1_t1c_*`（`nrw1_t1b_*` / `nrw1_t1_*` / `r7_*` exact-set を変更しない）。

### 12.5 Acceptance bar（implementation tranche 用; 今は未達）

1. Linux/macOS、GCC/Clang、Debug/Release strict
2. ASan/UBSan
3. oracle deterministic twice + full bridge consumption
4. equality/node-id gate全Hop vectorsをHostで実行し、ESP32-S3 targetでもmbedTLS T0 bundle、
   N6 derive、N6 node_id16を同じvector exact-setで実行一致。ESP compile/linkだけを実行証明に代用しない
5. tests-OFF package / private symbol / install leakage
6. stack gate + ESP final-link（target KATとは別の必要条件）
7. 既存 T0/T1/T1b/R6/N6 gates 無退行。limited withdrawal中のN6 candidate pinをAcceptedと
   仮定せず、T1c変更後source manifestを同一trancheで明示re-pinする。pin checker self-test・
   docs/07 exact manifest・GCC13・N6 full fault/mutation corpus・fresh independent reviewで
   新hashを直接再受入し、withdrawalを解消
8. independent review P0=P1=P2=0 + review record（**本 docs-only では作成しない**）

## 13. Ambiguity resolutions and rejected alternatives

### 13.1 採用決定（再質問せず反映済み）

1. tranche 名: **R7 T1c Authenticated Hop Fresh-Install Owner**（Hop 一方向のみ）
2. local-identity exact ABI / sole binder / INIT-only は **不変**; T1c は BOUND→BOOTED/READY 前提
3. authority は T1c-A opaque accepted token; raw stamp は production fail-closed のまま
4. Hop install token は M4 incomplete; claim は固定容量 copy-own; caller span 禁止
5. node_id は stable から KDF; closed mapping; bound local と一致
6. sole API は `install_hop_accepted`; 既存 install_hop を一般 token 化しない
7. owner 順序 §7 exact; token は consume 開始後 terminal
8. T1b discard + N6 derive は equality oracle 条件付きのみ（Required gate + N6 sole runtime）
9. CU: handle 0; recover_cu only; ALL_PROPOSED → secret 破棄 + DORMANT; 再注入禁止; no resume/M5
10. nonclaims §2.2; compile/link ≠ HIL
11. ownership/zero/alias/reentry/stack/CU exact
12. gates 定義のみ; 実装存在を偽装しない
13. docs-only Proposedでは docs/30–33 / ADR-0010–13 Normative/Accepted を編集しない。
    implementation acceptanceでは docs/30 private closed set とdocs/07/source pinを同時再受入

### 13.2 最強の代案比較

| 代案 | 概要 | 却下理由 |
| --- | --- | --- |
| **M4+M5+W1 一括** | handshake・resume・wire orchestration を同時実装 | failure domain が混線; T1b/N6 の独立監査が壊れる; CU/resume/M5 を未凍結のまま混ぜる |
| **derive 差替えだけ** | T1b を呼ばず N6 derive に expected digest を足すだけ | provenance token / stamp / node map / FULL linearization が残る; 「認証済み install」にならない |
| **bundle RAM 移行 + provider 統一** | T1b bundle を N6 slot に直接載せ T0 に一本化 | provider 二重系全体の移行監査が巨大; 本 tranche の fresh install 接続を遅延させる |
| **raw token fields** | claim に raw node_id / trusted bool / 生 capsule を置く | R6 §5.3.0 / §20.4 の fail-closed を迂回; local-identity accepted パターンと矛盾 |

採用: **薄い stateful owner** が M4 token → claim → T1b verified → N6 FULL を順序固定で接続する。

### 13.3 P0 resolution register（実装前に仕様でclosed）

| ID | 項目 | fixed resolution |
| --- | --- | --- |
| P0-A1 | stamp bind/refresh state | §3.3: INIT/BOUND/BOOTED/READY、same epoch + non-regressing now、1 fresh token generation/attempt |
| P0-B1 | claim exact byte size / packing | **272 bytes** + all offsets + ILP32/LP64 compile gate |
| P0-C1 | failure 時 `*out_handle` | NULL/overflow/ALIASはunchanged; valid disjoint後は0; successのみnonzero |
| P0-C2 | durable engine 共有 | private helper 抽出; fixture と T1c の双方から呼ぶ |
| P0-D1 | T1b bundle vs N6 derive | equality gate Required + runtime は N6 derive |
| P0-E1 | T1b provider 供給 | API の明示 immutable borrow; token consume 前 exact T0 ABI validate |
| P0-E2 | N6 private internals | accepted entries は N6 TU、pure preparation は新 T1c TU。raw authenticated capsule API なし |
| P0-E3 | N6 source pin | implementation と同時に docs/07 + pin authority を限定 re-accept。skip/旧hash偽装禁止 |
| P0-E4 | READY install CU | pre-state copy-own; ALL_OLD exact restore; ALL_PROPOSED全secret/handle invalidation+DORMANT |
| P0-E5 | node-id crypto | N6 TUがbound `&n6->crypto`をprivate prepare helperへborrow; caller注入なし |
| P0-E6 | CU kind isolation | closed install kind; namespace wipeはinstall CUだけ、TX/RX CU不変 |
| P0-E7 | ESP equality | final-linkとは別にESP32-S3 targetで全Hop vectorを実行一致 |
| P0-F1 | ALL_PROPOSED 後 state 名 | N6 既存 `DORMANT_DURABLE_NO_SECRET` にマップ; handle 0 固定 |

上表は仕様へ反映済みである。実装時はheader/CMakeだけでなく、N6 durable/CU変更、source
manifest、oracle/vector/mutation、Host/ESP final-linkを同じ候補SHAで機械 pinし、独立再監査する。
未解決として後送りしない。

## 14. Acceptance boundary and next steps

### 14.1 本章の状態

**Proposed / docs-only。** implementation candidate、CTest 緑、vector JSON 存在、
Accepted review、R7 full のいずれも **主張しない**。

### 14.2 後続 tranche（非範囲の順序指針）

1. T1c implementation candidate + equality/oracle/gates + independent review
2. E2E authenticated fresh-install owner（Hop と分離）
3. M5 resume / secret rehydrate
4. W1 が T1 codec + N6 lease を orchestration
5. provider 統一（T1c限定 N6 source re-pin は implementation tranche 内で先に完了）
6. RF/USB HIL、legal、production radio

### 14.3 Related

- [docs/30](30-r6-secure-radio-wire.md) · [ADR-0010](adr/0010-r6-secure-radio-wire.md)
- [docs/31](31-r7-crypto-provider-and-aead.md) · [ADR-0011](adr/0011-r7-crypto-provider-boundary.md)
- [docs/32](32-r7-t1-nrw1-single-wire-codec.md) · [ADR-0012](adr/0012-r7-t1-nrw1-single-wire-codec.md)
- [docs/33](33-r7-t1b-context-binding-hkdf.md) · [ADR-0013](adr/0013-r7-t1b-context-binding-hkdf.md)
- [ADR-0014](adr/0014-r7-t1c-authenticated-hop-fresh-install-owner.md)
- private sources (read-only reference): `src/radio/n6_context_store.{h,c}` ·
  `n6_crypto_provider.h` · `n6_crypto_host.c` · `r7_context_binding.{h,c}`
