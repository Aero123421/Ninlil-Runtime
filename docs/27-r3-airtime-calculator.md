# 27. R3 LoRa Airtime Calculator（Normative freeze / host candidate）

状態: **Normative**（R3 host implementation candidate; **main 未リリースの最初の freeze**）<br>
対象: SX1262 LoRa 入力の決定的 ToA（µs）算出<br>
非対象: R4/R5/R2 runtime body / FSK / Japan production 数値 / duty·LBT·legal / RF·HIL / public ABI / **independent re-review GO**

正本 API: [`src/radio/airtime_calculator.h`](../src/radio/airtime_calculator.h)<br>
決定記録: [ADR-0007](adr/0007-r3-airtime-calculator.md)<br>
R2 受渡し: [24章 §9](24-r2-physical-compliance-permit-authority.md)

---

## 0. 主張境界

| 言えること | 言えないこと |
| --- | --- |
| closed domain で決定的 `airtime_us`（ceil） | Japan / legal / duty |
| R2 per-permit `max_airtime_us` **候補** | R2 body / R3 complete |
| uint64 有理 + independent oracle 一致 | 実電波 ToA / HIL |
| 公式 driver **numerator/BW** と整合 | 公式 **uint32 ms wrapper** を正本にしたこと |

**SEMANTIC: R3_HOST_CANDIDATE_ONLY**

---

## 1. 出典 pin

### 1.1 一次実装 algebra（ToA 分子 / BW Hz）

| 項目 | 値 |
| --- | --- |
| Repo | Lora-net/sx126x_driver |
| Tag | **v2.3.2**（ToA helper は CR 1..4 のみ; latest v2.5 系も同様） |
| Commit | **`9636dc4660ada4eeddf91eb7b3f7f241000bf202`** |
| File | `src/sx126x.c` |
| Functions | `sx126x_get_lora_time_on_air_numerator`、`sx126x_get_lora_bw_in_hz` |

**禁止:** `sx126x_get_lora_time_on_air_in_ms` の戻りを oracle に丸写しすること。
同関数は `uint32_t numerator = 1000U * U` により合法最大級で wrap し、誤 ms（例: 494718）を返す。正本は **uint64 exact rational**。

### 1.2 Datasheet（DS.SX1261-2.W.APP **Rev 2.2**, Dec 2024）

| 節 | 内容 |
| --- | --- |
| **§6.1.4 p41** | LoRa Time-on-Air → SX126x driver 参照 |
| **§6.1.1.4 p40** / **§13.4.5 p90** | LDRO。推奨 **Ts ≥ 16.38 ms** |
| **§13.4.5.2 p92** | BW / SF / CR |
| **§6.1.1.1 p38** | SF5/6 **推奨 preamble 12**（式には混ぜない; R5 policy） |

### 1.3 formula_version

**1** — 本 freeze の初版（破壊的変更時のみ上げる）。

---

## 2. Closed domain

### 2.1 SF ∈ {5..12}

### 2.2 BW Hz（driver exact only）

7812, 10417, 15625, 20833, 31250, 41667, 62500, 125000, 250000, 500000
任意近似 **禁止**。

### 2.3 CR ∈ {1..4} only

DS long-interleaving raw **0x05..0x07** は存在するが、公式 ToA helper は **1..4 のみ**。
**cr∈{5,6,7} → `INVALID_ARGUMENT`**。外挿禁止。
**SEMANTIC: CR_LONG_INTERLEAVE_5_7_REJECT**

### 2.4 Header / CRC / preamble / payload

| field | domain |
| --- | --- |
| header | explicit(0)/implicit(1) |
| CRC | off/on |
| preamble | **[6, 65535]**（math） |
| payload | [0, 255] |

SF5/6 推奨 preamble **12**（DS §6.1.1.1 p38）は **R5 profile policy**。R3 math は ≥6。

### 2.5 LDRO OFF / ON / AUTO

| 入力 | SF | `ldro_effective` | 代数への DE |
| --- | ---: | ---: | --- |
| OFF | any | 0 | SF≥7 のみ分母に使用 |
| ON | any（**SF5/6 含む**） | **1** | SF≥7 のみ分母に使用。**SF5/6 は DE を分母等に使わない** |
| AUTO | any | §4（≥16.38 ms） | 同上。closed BW では SF5/6 は通常 0 |

**SEMANTIC: SF56_LDRO_ON_ACCEPTED** — SF5/6 で LDRO_ON を `UNSUPPORTED` にしてはならない。

---

## 3. Equations（driver numerator, uint64）

\[
\begin{aligned}
N_{\mathrm{ceil}} &= 8\mathrm{PL}+16\mathrm{CRC}-4\mathrm{SF}
 +(\mathrm{explicit}?20:0)+(\mathrm{SF}\ge7?8:0)\\
D &= \begin{cases}4\mathrm{SF}&\mathrm{SF}\le6\\4(\mathrm{SF}-2)&\mathrm{SF}\ge7\land\mathrm{DE}=1\\4\mathrm{SF}&\mathrm{SF}\ge7\land\mathrm{DE}=0\end{cases}\\
C&=\lceil N_{\mathrm{ceil}}/D\rceil\quad(N_{\mathrm{ceil}}{<}0\Rightarrow0)\\
I&=C(\mathrm{CR}+4)+N_{\mathrm{pre}}+12+(\mathrm{SF}\le6?2:0)\\
U&=(4I+1)\cdot 2^{\mathrm{SF}-2}\quad(\mathbf{uint64})\\
T_{\mathrm{ms}}&=\lceil 1000\cdot U/\mathrm{BW}\rceil\\
T_{\mathrm{us}}&=\lceil 10^{6}\cdot U/\mathrm{BW}\rceil
\end{aligned}
\]

**SEMANTIC:** `SF56_EXPLICIT_PLUS20_IMPLICIT_PLUS0` / `SF56_EXTRA_PLUS2_SYMBOLS` / `SF7_PLUS_NUM_PLUS8` / `TOA_NUMERATOR_UINT64_EXACT` / `SF56_LDRO_ON_ACCEPTED_DE_UNUSED_IN_ALGEBRA`

### 3.1 `n_payload_symbols` 診断値と SF5/6 の +2

| 量 | 定義 | SF5/6 の +2 を含むか |
| --- | --- | --- |
| **`n_payload_symbols`** | \(8 + C\cdot(\mathrm{CR}+4)\) | **含まない**（payload 部のみの診断） |
| **中間 \(I\)** | payload 寄与 + preamble + 12 **[+2 if SF≤6]** | **含む**（ToA に効く） |
| **`airtime_us`** | \(\lceil 10^{6} U/\mathrm{BW}\rceil\), \(U=(4I+1)2^{\mathrm{SF}-2}\) | +2 は \(I\) 経由で反映 |

実装が `n_payload_symbols` から ToA を再構成する場合、SF5/6 では **別途 +2 を \(I\) に入れないと under-estimate** になる。正本は常に §3 の \(U\)。

### 3.2 `airtime_us` の uint32 overflow（fail-closed）

| 条件 | status | 動作 |
| --- | --- | --- |
| \(T_{\mathrm{us}} > \mathrm{UINT32\_MAX}\) | **`OVERFLOW`** | `out` を zero。**短く切捨てた µs を返さない**（fail-closed） |
| uint64 乗算不能 | `OVERFLOW` | 同上 |

R2 `max_airtime_us` は u32 のため、OVERFLOW は issue 不可として扱う。

**合法最大例:** SF=12, BW=7812, CR=4, pre=65535, PL=255, explicit, CRC on, DE=1:

| 量 | 値 |
| --- | ---: |
| U | 270152704 |
| ceil-ms（uint64） | **34581760** |
| 公式 uint32 ms wrapper 誤値 | **494718**（採用禁止） |
| ceil-us | 34581759345 → API **`OVERFLOW`** |

### 3.3 High-value ceil-ms pins

| 条件 | ceil-ms | notes |
| --- | ---: | --- |
| SF7 BW125 pre8 CR1 explicit noCRC P0 | 21 | |
| P3 / P4 / P5 explicit | 26 / 31 / 31 | |
| P5 implicit | 26 | |
| SF5 BW125 pre12 CR1 explicit CRC P16 **LDRO_OFF** | 17 | effective=0 |
| same **LDRO_ON** | **17** | effective=1; ToA 同一（DE 非使用） |
| SF6 BW125 pre12 CR4 implicit noCRC P16 | 34 | |
| SF11 BW125 pre8 CR1 explicit CRC P16 DE0/DE1 | 578 / 660 | |
| SF12 BW250 DE1 | 660 | |

---

## 4. LDRO AUTO policy（formula law ではない）

\[
\mathrm{DE}=1 \iff 2^{\mathrm{SF}}\cdot 100000 \ge \mathrm{BW}\cdot 1638
\]

（Ts ≥ 16.38 ms、**等号含む**。）
**SEMANTIC: LDRO_AUTO_GE_16P38_MS**

R4/R5: radio に program する DE と `ldro_effective` の exact 一致を後続で閉じる。

---

## 5. Errors

OK / INVALID_ARGUMENT / UNSUPPORTED / OVERFLOW / STRUCT — 失敗時 out **zero**（partial fill 禁止）。

UNSUPPORTED の主用途: closed BW 外など。**SF5/6 + LDRO_ON は UNSUPPORTED ではない**。

---

## 6. R2 受渡し

`airtime_us` → per-permit `max_airtime_us`。OVERFLOW 時は issue 不可。ceiling は R5。

---

## 7. Oracle / gate

- independent Fraction + uint64; wrapper 非コピー
- SF5 DE0/DE1 高価値ベクトル（ON を実渡し）
- mutations: SF5/6 ON 拒否 / ON→OFF 置換 / SF5/6 へ DE 誤適用 / 旧 BW / 式破壊 等

### 7.1 Vector freshness / determinism（Required）

**SEMANTIC: VECTORS_FRESH_DETERMINISTIC**

| 成果物 | 生成 |
| --- | --- |
| `tests/radio/airtime_r3_vectors.json` | `python3 tools/airtime_r3_oracle.py emit-json --out …` |
| `tests/radio/airtime_r3_vectors.gen.h` | `python3 tools/airtime_r3_oracle.py emit-c --out …` |

`airtime_r3_gate` **check** は次を **必須**:

1. 独立 temp dir で oracle を **2 回**実行し JSON/header を各回生成（source tree に書かない）
2. **run1 == run2**（byte 完全一致; determinism）
3. 各成果物が **committed と byte-for-byte 一致**（stale / 手編集禁止）

手編集や生成忘れは gate FAIL。bridge は committed header を読むため、freshness 無しでは false-green になり得る — **gate がそれを閉じる**。

---

## 8. Packaging

`airtime_calculator.c` のみ private。oracle / JSON / `.gen.h` / bridge **非混入**。public 非露出。

---

## 9. Acceptance

- [x] formula_version **1**（最初の freeze）
- [x] driver + DS Rev 2.2 pins
- [x] SF5/6 LDRO_ON 受理・DE 非使用
- [x] LDRO AUTO ≥16.38 ms
- [x] CR 5..7 reject; closed BW; uint64
- [x] n_payload vs +2 と overflow fail-closed 明記
- [x] vector freshness/determinism gate（§7.1）
- [x] nonclaims

---

## 10. 関連

[05](05-security-and-compliance.md) [07](07-testing-and-quality.md) [09](09-roadmap.md) [23](23-usb-radio-boundary.md) [24](24-r2-physical-compliance-permit-authority.md) [ADR-0007](adr/0007-r3-airtime-calculator.md)
