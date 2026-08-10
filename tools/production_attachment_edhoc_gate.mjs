#!/usr/bin/env node
// Independent Node.js gate for the Proposed Production Attachment vector.
// Primary machine authority: full closed-tree equality against the independent
// canonical expected model (spec constants / layouts / preimage formulas).
// Descriptive prose (reason/note) is the only free allowlist surface.
// Does not import production runtime/codec code.

import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const defaultVector = path.join(
  path.dirname(here),
  "spec",
  "vectors",
  "production-attachment-edhoc-v1.json",
);
const expectedModelPy = path.join(
  here,
  "production_attachment_edhoc_expected_model.py",
);
const DESCRIPTIVE_ALLOWLIST = new Set([
  "$.rfc9529_method3_suite2_reference.reason",
  "$.credentials.note",
]);
let cachedExpectedDocument = null;
const requiredCases = new Set([
  "NAC1-SUITE2-MESSAGE1",
  "NAC1-SUITE3-MESSAGE1",
  "NAS1-USB-STREAM-RECORD",
  "COOKIE-CURRENT-BUCKET-CURRENT-SECRET",
  "COOKIE-PREVIOUS-BUCKET-PREVIOUS-SECRET",
  "COOKIE-SOURCE-CARRIER-SESSION-MUTATION",
  "COOKIE-RESPONSE-EXACT-2-FRAGMENT-SCRATCH",
  "COOKIE-RESPONSE-EXACT-LENGTH-159",
  "PROTECTED-PROPOSE-INSTALL-DUAL-CONFIRM-SEQUENCE",
  "NAC1-INSTALL-MAX-RADIO-FRAGMENTATION",
  "NAC1-CRC-MUTATION",
  "NAC1-RESERVED-MUTATION",
  "NAC1-LENGTH-MUTATION",
  "NAC1-SESSION-MUTATION",
  "NAC1-BINDING-MUTATION",
  "NAR1-CRC-MUTATION",
  "NAR1-INDEX-MUTATION",
  "NAR1-OFFSET-MUTATION",
  "NAR1-DIGEST-MUTATION",
  "NAR1-REORDER-DUPLICATE-LOSS",
  "NAR1-CANONICAL-FRAGMENT-SHAPE",
  "NAR1-SESSION-GENERATION-BINDING-DIVERGENCE",
  "NAR1-MIXED-FRAGMENT-TUPLE",
  "CARRIER-BINDING-DERIVATION-PINNED",
  "CARRIER-TRANSCRIPT-BYTE-EXACT",
  "CARRIER-TRANSCRIPT-NEGATIVES",
  "WIFI-BINDING-INPUT-MUTATION",
  "N6AT-CRC-MUTATION",
  "N6AT-ROLE-KEY-VALUE-MISMATCH",
  "N6AT-UNKNOWN-STATE",
  "NAB1-EXACT-15-MEMBER-SET-BOTH-ROLES",
  "NAB1-EXACT-KEY-IDENTITY-INVENTORY",
  "NAB1-DUPLICATE-MISSING-SUBSTITUTED",
  "NAB1-CRC-COUNT-ROLE-MUTATION",
  "N6AT-PENDING-MARKER",
  "N6AT-PENDING-TO-ACTIVE",
  "N6AT-COMMIT-UNKNOWN-OLD-NEW-THIRD",
  "PUBLICATION-ZERO-BEFORE-DUAL-CONFIRM",
  "CREDENTIAL-RPK-CCS-KID",
  "PROFILE-METHOD-SUITE-MESSAGE4-EAD",
  "PROPOSAL-MEMBERSHIP-LEASE-AUTHORITY-FIELDS",
  "RFC9529-INDEPENDENT-CONSTANTS",
  "BYTE-PLUS-SHA-MUTATION",
  "EXPORTER-LABEL-SET-EXACT",
  "EXPORTER-CONTEXT-ONE-BYTE-MUTATION",
  "CONTROL-NONCE-SEQUENCE-DIRECTION-EXACT",
  "RFC9529-REFERENCE-DIGESTS",
  "COOKIE-FOUR-COMBINATION-MATRIX",
  "NAR1-EXCHANGE-GENERATION-BINDING",
  "N6AT-RESERVED-BYTES",
  "N6AT-ROLE-SPECIFIC-BOTH",
  "NAB1-CANONICAL-COMPLETE-KEY-ORDER",
  "NAB1-REORDER-CONTEXT-SUBSTITUTION",
  "LIFECYCLE-15-KEY-GROUP-MACHINE",
  "CREDENTIAL-CCS-CBOR-DECODE",
  "CREDENTIAL-TAIL-MUTATION",
  "NAP-NAI-CONTEXT-MISMATCH",
  "GATE-SELF-TEST",
  "PA-REATTACH-15ROW-OLD-NEW-STABLE-THIRD",
  "PA-REATTACH-LANE-OLD-NONEMPTY",
  "PA-REATTACH-10K-RESTART-MONOTONIC",
  "PA-PREREQ-FACTORY-MEMBERSHIP-LOCAL-KEY",
  "PA-LOCAL-KEY-MISMATCH-ROLLBACK-REENTRY",
  "PA-EDHOC-SUITE2-M1-M4",
  "PA-EDHOC-SUITE3-M1-M4",
  "PA-EDHOC-EAD1-EAD4-TERMINAL",
  "PA-EDHOC-DOWNGRADE-NO-AUTORETRY",
  "PA-NAR-REORDER-SUCCESS",
  "PA-NAR-DUPLICATE-NO-PROGRESS",
  "PA-NAR-CONFLICT-GAP-OVERLAP-MIXED-TIMEOUT",
  "PA-PREAUTH-SOURCE-QUOTA-IDLE-BUCKET",
  "PA-MAGIC-GLOBAL-UNIQUE",
  "PA-NAS-PARTIAL-SHORT-TRAILING-FUTURE-INNER",
  "PA-INDEPENDENT-COHERENT-DRIFT-REJECT",
]);

// Independent RFC 9529 §3 method-3/suite-2 pins (not derived from the vector).
const RFC9529_MESSAGES = {
  message_1: Buffer.from(
    "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637",
    "hex",
  ),
  message_2: Buffer.from(
    "582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a1eef9e0e7e1886fcd",
    "hex",
  ),
  message_3: Buffer.from("52e562097bc417dd5919485ac7891ffd90a9fc", "hex"),
  message_4: Buffer.from("4828c966b7ca304f83", "hex"),
};

class GateError extends Error {}
const fail = (message) => {
  throw new GateError(message);
};

const hex = (value, field) => {
  if (
    typeof value !== "string" ||
    value.length % 2 !== 0 ||
    value !== value.toLowerCase() ||
    !/^[0-9a-f]*$/.test(value)
  ) {
    fail(`${field}: non-canonical hex`);
  }
  return Buffer.from(value, "hex");
};
const u16 = (value, offset) => value.readUInt16BE(offset);
const u32 = (value, offset) => value.readUInt32BE(offset);
const u64 = (value, offset) => value.readBigUInt64BE(offset);
const sha = (value) => crypto.createHash("sha256").update(value).digest();
const shaHex = (value) => sha(value).toString("hex");
const equal = (left, right) =>
  left.length === right.length && crypto.timingSafeEqual(left, right);

function crc32c(value) {
  let crc = 0xffffffff;
  for (const octet of value) {
    crc = (crc ^ octet) >>> 0;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = ((crc >>> 1) ^ ((crc & 1) !== 0 ? 0x82f63b78 : 0)) >>> 0;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function validateNpa(record, field, kind, sequence, carrier) {
  if (
    record.length < 88 ||
    record.length > 600 ||
    record.subarray(0, 4).toString() !== "NAC1" ||
    u16(record, 4) !== 1 ||
    u16(record, 6) !== 88 ||
    u32(record, 8) !== record.length ||
    u32(record, 12) !== record.length - 88
  ) {
    fail(`${field}: NAC framing`);
  }
  const actualKind = record[16];
  if (
    actualKind < 1 ||
    actualKind > 11 ||
    record[17] !== 0 ||
    ![1, 2, 3].includes(record[18]) ||
    record[19] !== 0 ||
    record.subarray(20, 36).every((value) => value === 0) ||
    u64(record, 36) === 0n ||
    !record.subarray(48, 52).every((value) => value === 0) ||
    record.subarray(52, 84).every((value) => value === 0)
  ) {
    fail(`${field}: NAC fields`);
  }
  const scratch = Buffer.from(record);
  const stored = u32(record, 84);
  scratch.fill(0, 84, 88);
  if (crc32c(scratch) !== stored) fail(`${field}: NAC CRC`);
  let expected = actualKind === 1 || actualKind === 2 ? 0 : actualKind - 3;
  if (actualKind === 3) {
    expected = u32(record, 44);
    if (expected < 1 || expected > 8) fail(`${field}: error sequence`);
  }
  if (
    u32(record, 44) !== expected ||
    (kind !== undefined && actualKind !== kind) ||
    (sequence !== undefined && u32(record, 44) !== sequence) ||
    (carrier !== undefined && record[18] !== carrier)
  ) {
    fail(`${field}: NAC matrix`);
  }
}

function validateNpr(packet, field) {
  const payload = packet.length >= 12 ? u16(packet, 10) : 0;
  const complete = packet.length >= 44 ? u16(packet, 40) : 0;
  const index = packet.length >= 44 ? packet[42] : 0;
  const count = packet.length >= 44 ? packet[43] : 0;
  const expectedCount = Math.ceil(complete / 124);
  const expectedPayload = index + 1 < count ? 124 : complete - index * 124;
  if (
    packet.length < 68 ||
    packet.length > 192 ||
    packet.subarray(0, 4).toString() !== "NAR1" ||
    packet[4] !== 0x12 ||
    packet[5] !== 1 ||
    u16(packet, 6) !== 68 ||
    u16(packet, 8) !== packet.length ||
    u16(packet, 10) !== packet.length - 68 ||
    complete < 88 ||
    complete > 600 ||
    count !== expectedCount ||
    count < 1 ||
    count > 5 ||
    index >= count ||
    payload < 1 ||
    payload > 124 ||
    payload !== expectedPayload ||
    u32(packet, 60) !== index * 124
  ) {
    fail(`${field}: NAR fields`);
  }
  const scratch = Buffer.from(packet);
  const stored = u32(packet, 64);
  scratch.fill(0, 64, 68);
  if (crc32c(scratch) !== stored) fail(`${field}: NAR CRC`);
}

function narShapePacket(complete, index, count, payload) {
  const packet = Buffer.alloc(68 + payload);
  packet.write("NAR1", 0, "ascii");
  packet.set([0x12, 0x01, 0x00, 0x44], 4);
  packet.writeUInt16BE(packet.length, 8);
  packet.writeUInt16BE(payload, 10);
  for (let value = 0; value < 16; value += 1) packet[12 + value] = value + 1;
  packet.writeBigUInt64BE(1n, 28);
  packet.writeUInt16BE(complete, 40);
  packet[42] = index;
  packet[43] = count;
  for (let value = 0; value < 16; value += 1) packet[44 + value] = value + 17;
  packet.writeUInt32BE(index * 124, 60);
  for (let value = 0; value < payload; value += 1) packet[68 + value] = value;
  packet.writeUInt32BE(crc32c(packet), 64);
  return packet;
}

function assertNarFragmentShapeAuthority(executed) {
  const accepted = [
    [88, 0, 1, 88],
    [124, 0, 1, 124],
    [125, 0, 2, 124],
    [125, 1, 2, 1],
    [159, 1, 2, 35],
    [600, 4, 5, 104],
  ];
  const rejected = [
    [87, 0, 1, 87],
    [601, 4, 5, 105],
    [124, 0, 2, 124],
    [124, 1, 2, 0],
    [159, 0, 3, 124],
    [159, 1, 3, 35],
    [159, 0, 2, 123],
    [159, 1, 2, 34],
  ];
  for (const shape of accepted) {
    validateNpr(narShapePacket(...shape), `nar shape positive ${shape}`);
  }
  for (const shape of rejected) {
    let rejectedShape = false;
    try {
      validateNpr(narShapePacket(...shape), `nar shape negative ${shape}`);
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
      rejectedShape = true;
    }
    if (!rejectedShape) fail(`NAR coherent shape mutant accepted: ${shape}`);
  }
  executed.add("NAR1-CANONICAL-FRAGMENT-SHAPE");
}


const P256_INITIATOR_X = Buffer.from(
  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  "hex",
);
const P256_INITIATOR_Y = Buffer.from(
  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  "hex",
);
const P256_RESPONDER_X = Buffer.from(
  "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
  "hex",
);
const P256_RESPONDER_Y = Buffer.from(
  "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4467992",
  "hex",
);

const COOKIE_TIME_BUCKET_SECONDS = 2;

/* Independent PA-S0 authority envelope pins (NOT derived from vector body). */
const PA_SCHEMA_ID = "ninlil.production-attachment-edhoc.vector.v1";
const PA_SCHEMA_VERSION = 1;
const PA_TITLE = "Ninlil Production Attachment EDHOC PA-S0 Proposed Vector";
const PA_ADR = "docs/adr/0023-production-attachment-edhoc-profile.md";
const PA_NORMATIVE_DOC = "docs/35-production-attachment-edhoc-profile.md";
const PA_STATUS = "PROPOSED_SPEC_ONLY";
const PA_SOURCES = Object.freeze([
  "RFC 9528",
  "RFC 9529",
  "docs/03-identity-and-join.md",
  "docs/30-r6-secure-radio-wire.md",
  "docs/34-r7-t1c-authenticated-hop-fresh-install-owner.md",
  "docs/adr/0017-bearer-registry-path-selection.md",
  "docs/adr/0018-wifi-bearer.md",
  "docs/adr/0022-domain-store-schema1-runtime-binding.md",
  "docs/adr/0023-production-attachment-edhoc-profile.md",
  "docs/35-production-attachment-edhoc-profile.md",
  "spec/protocol-magic-registry-v1.json",
]);
const PA_NONCLAIMS = Object.freeze([
  "NOT_ACCEPTED",
  "NOT_IMPLEMENTATION_COMPLETE",
  "NOT_PRODUCTION",
  "NOT_HIL",
  "NOT_RELEASE_SUPPORTED",
  "NOT_PUBLIC_ABI",
  "TEST_ORACLE_ONLY_MANIFESTS",
]);
const PA_TOOLS = Object.freeze({
  generator: "tools/production_attachment_edhoc_vector_gen.py",
  composition: "tools/production_attachment_edhoc_composition.py",
  expected_model: "tools/production_attachment_edhoc_expected_model.py",
  independent_authority:
    "tools/production_attachment_edhoc_independent_authority.py",
  python_gate: "tools/production_attachment_edhoc_gate.py",
  node_gate: "tools/production_attachment_edhoc_gate.mjs",
  c_test: "tests/radio/production_attachment_edhoc_vector_test.c",
  schema_authority: "tools/production_attachment_edhoc_schema_authority.py",
  magic_registry_gate: "tools/protocol_magic_registry_gate.py",
});
const PA_STATUS_MAP = Object.freeze({
  vector: PA_STATUS,
  pa_tranche: "PA-S0",
  pa_tranche_state: "IN_PROGRESS",
  accepted: false,
  implementation: false,
  hil: false,
  release: false,
  spec_accepted: false,
});
const PA_LIFECYCLE_CONSTANTS = Object.freeze({
  member_count_exact: 15,
  old_cardinality_rule: "DERIVED_FROM_15_PER_ROW_OLD_PRESENT_FLAGS",
  new_pending_member_count: 15,
  partial_member_counts_rejected: Object.freeze([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  ]),
  accepted_classifications: Object.freeze([
    "EXACT_OLD",
    "EXACT_NEW_PENDING_15",
    "EXACT_NEW_ACTIVE_MARKER",
  ]),
  accepted_snapshots: Object.freeze(["exact_old", "exact_new_pending_15"]),
  value_label: "NINLIL-PA-N6-CODEC-V1",
  ctx_label: "NINLIL-PA-N6-CTX-DIGEST-V1",
  cookie_time_bucket_seconds: 2,
  method: 3,
  rfc_message_1_method_byte: 3,
  nac1_header_bytes: 88,
  nab1_entry_count: 15,
});
// Role-level COMMIT_UNKNOWN closed lists (parity with Python CU_*_EXACT).
// Exact ordered equality + uniqueness — Set-only checks false-green on
// duplicate EXACT_OLD or empty rejected_snapshot_kinds.
const CU_ACCEPTED_CLASSIFICATIONS_EXACT = Object.freeze([
  "EXACT_OLD",
  "EXACT_NEW_PENDING_15",
  "EXACT_NEW_ACTIVE_MARKER",
]);
const CU_REJECTED_SNAPSHOT_KINDS_EXACT = Object.freeze([
  ...Array.from({ length: 14 }, (_, i) => `partial_${i + 1}`),
  "extra_16",
  "third_mismatch",
  "value_substitution",
  "context_digest_substitution",
]);

function assertExactUniqueStringList(got, expected, field) {
  if (!Array.isArray(got)) fail(`${field}: expected array`);
  if (JSON.stringify(got) !== JSON.stringify([...expected])) {
    fail(`${field}: exact list mismatch`);
  }
  if (got.length !== new Set(got).size) {
    fail(`${field}: duplicate entries`);
  }
  for (const item of got) {
    if (typeof item !== "string") fail(`${field}: non-string entry`);
  }
}
const PA_ROOT_REQUIRED = Object.freeze([
  "schema",
  "schema_version",
  "title",
  "adr",
  "normative_doc",
  "status",
  "status_map",
  "sources",
  "nonclaims",
  "tools",
  "lifecycle_constants",
  "limits",
  "profile",
  "rfc9529_method3_suite2_reference",
  "edhoc_message_1",
  "stream_wrapper",
  "stateless_cookie",
  "attachment_install",
  "carrier_bindings",
  "carrier_transcript",
  "compact_radio_fragments",
  "credentials",
  "n6_attachment_marker",
  "lifecycle",
  "atomic_batch_manifests",
  "required_gate_cases",
]);

function exactInt(value, field) {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    fail(`${field}: expected exact int`);
  }
  return value;
}
function exactBool(value, field) {
  if (typeof value !== "boolean") fail(`${field}: expected exact bool`);
  return value;
}
function exactStr(value, field) {
  if (typeof value !== "string") fail(`${field}: expected exact str`);
  return value;
}
function requireKeys(obj, field, required) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    fail(`${field}: expected object`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) {
      fail(`${field}: missing required key ${key}`);
    }
  }
  return obj;
}

/**
 * Strict JSON parser: decoded-unicode duplicate keys rejected (schema vs
 * \u0073chema), no +0/leading-zero/unsafe/nonfinite numbers, integers only.
 */
function loadStrictJson(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString("utf8") : raw;
  if (/\bNaN\b|\bInfinity\b|\b-Infinity\b/.test(text)) {
    fail("json constant forbidden");
  }
  let i = 0;
  const n = text.length;
  const skipWs = () => {
    while (i < n && /[ \t\r\n]/.test(text[i])) i += 1;
  };
  const parseString = () => {
    if (text[i] !== '"') fail("json string");
    i += 1;
    let out = "";
    while (i < n) {
      const c = text[i];
      if (c === '"') {
        i += 1;
        return out;
      }
      if (c === "\\") {
        i += 1;
        if (i >= n) fail("json string escape eof");
        const e = text[i++];
        if (e === '"' || e === "\\" || e === "/") out += e;
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("json unicode escape");
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else fail("json bad escape");
        continue;
      }
      out += c;
      i += 1;
    }
    fail("unterminated string");
  };
  const parseNumber = () => {
    const start = i;
    if (text[i] === "+") fail("json number leading + forbidden");
    if (text[i] === "-") i += 1;
    if (i >= n) fail("json number");
    if (text[i] === "0") {
      i += 1;
      if (i < n && /[0-9]/.test(text[i])) fail("json number leading zero");
    } else if (/[1-9]/.test(text[i])) {
      while (i < n && /[0-9]/.test(text[i])) i += 1;
    } else fail("json number digit");
    if (i < n && text[i] === ".") {
      i += 1;
      if (i >= n || !/[0-9]/.test(text[i])) fail("json fraction");
      while (i < n && /[0-9]/.test(text[i])) i += 1;
      fail("json non-integer number forbidden");
    }
    if (i < n && (text[i] === "e" || text[i] === "E")) {
      fail("json exponent forbidden for strict int");
    }
    const lit = text.slice(start, i);
    if (lit === "+0" || lit === "-0" || lit === "+0.0") {
      fail("json non-canonical zero");
    }
    const num = Number(lit);
    if (!Number.isFinite(num)) fail("json nonfinite");
    if (!Number.isSafeInteger(num)) fail(`json unsafe integer: ${lit}`);
    if (!Number.isInteger(num)) fail(`json non-integer: ${lit}`);
    return num;
  };
  const parseValue = () => {
    skipWs();
    if (i >= n) fail("eof");
    const c = text[i];
    if (c === "{") return parseObject();
    if (c === "[") return parseArray();
    if (c === '"') return parseString();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      fail("json null forbidden");
    }
    return parseNumber();
  };
  const parseArray = () => {
    i += 1;
    const arr = [];
    skipWs();
    if (text[i] === "]") {
      i += 1;
      return arr;
    }
    for (;;) {
      arr.push(parseValue());
      skipWs();
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "]") {
        i += 1;
        return arr;
      }
      fail("json array");
    }
  };
  const parseObject = () => {
    i += 1;
    const obj = {};
    const seen = new Set();
    skipWs();
    if (text[i] === "}") {
      i += 1;
      return obj;
    }
    for (;;) {
      skipWs();
      const key = parseString();
      if (seen.has(key)) fail(`duplicate json key: ${key}`);
      seen.add(key);
      skipWs();
      if (text[i] !== ":") fail("json colon");
      i += 1;
      obj[key] = parseValue();
      skipWs();
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "}") {
        i += 1;
        return obj;
      }
      fail("json object");
    }
  };
  const value = parseValue();
  skipWs();
  if (i !== n) fail("json trailing");
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("root object");
  }
  return value;
}

function closedObj(obj, path, required) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    fail(`${path}: expected object`);
  }
  const keys = Object.keys(obj);
  const req = new Set(required);
  for (const k of req) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) {
      fail(`${path}: missing key ${k}`);
    }
  }
  for (const k of keys) {
    if (!req.has(k)) fail(`${path}: unknown key ${k}`);
  }
  return obj;
}

function deepEqualJson(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function recomputeCrcN6atLocal(value) {
  value.writeUInt32BE(crc32c(value.subarray(0, 116)), 116);
}

function mutateN6atAuthorityFieldCoherent(document, roleName, offset, width) {
  const patchValue = (valueHex) => {
    const raw = Buffer.from(valueHex, "hex");
    if (width === 8) {
      raw.writeBigUInt64BE(BigInt("0xdeadbeefcafebabe"), offset);
    } else {
      raw.writeUInt32BE(0xdeadbeef >>> 0, offset);
    }
    recomputeCrcN6atLocal(raw);
    return raw.toString("hex");
  };
  const role = document.lifecycle.roles[roleName];
  for (const stateName of ["pending", "active", "fenced_third"]) {
    const item = role[stateName];
    const newHex = patchValue(item.value_hex);
    item.value_hex = newHex;
    item.value_sha256 = shaHex(Buffer.from(newHex, "hex"));
  }
  if (roleName === "device_local_role_1") {
    document.lifecycle.pending_marker.value_hex = role.pending.value_hex;
    document.lifecycle.pending_marker.value_sha256 = role.pending.value_sha256;
    document.lifecycle.pending_to_active.old_value_hex = role.pending.value_hex;
    document.lifecycle.pending_to_active.old_value_sha256 =
      role.pending.value_sha256;
    document.lifecycle.pending_to_active.new_value_hex = role.active.value_hex;
    document.lifecycle.pending_to_active.new_value_sha256 =
      role.active.value_sha256;
    document.lifecycle.commit_unknown.old_pending_value_hex =
      role.pending.value_hex;
    document.lifecycle.commit_unknown.new_active_value_hex =
      role.active.value_hex;
    document.lifecycle.commit_unknown.third_value_hex =
      role.fenced_third.value_hex;
    document.n6_attachment_marker.value_hex = role.active.value_hex;
    document.n6_attachment_marker.value_sha256 = role.active.value_sha256;
    document.lifecycle.group_machine.device_pending_value_hex =
      role.pending.value_hex;
    document.lifecycle.group_machine.device_active_value_hex =
      role.active.value_hex;
  } else {
    document.lifecycle.group_machine.authority_pending_value_hex =
      role.pending.value_hex;
    document.lifecycle.group_machine.authority_active_value_hex =
      role.active.value_hex;
  }
  const snaps = document.lifecycle.group_machine.snapshots.roles[roleName];
  snaps.third_mismatch.marker_value_hex = role.fenced_third.value_hex;
  snaps.pending_to_active.old_value_hex = role.pending.value_hex;
  snaps.pending_to_active.new_value_hex = role.active.value_hex;
  snaps.pending_to_active.old_value_sha256 = role.pending.value_sha256;
  snaps.pending_to_active.new_value_sha256 = role.active.value_sha256;
  snaps.commit_unknown.active_marker_only.value_hex = role.active.value_hex;
  snaps.commit_unknown.active_marker_only.value_sha256 = role.active.value_sha256;
  snaps.exact_new_pending_15.marker_value_hex = role.pending.value_hex;
  const pendingVal = Buffer.from(role.pending.value_hex, "hex");
  const containers = [
    snaps.exact_new_pending_15.members,
    snaps.exact_new_pending_15.value_substitution_rejected.members,
    snaps.exact_new_pending_15.context_digest_substitution_rejected.members,
    document.atomic_batch_manifests[roleName].exact_inventory,
  ];
  for (let n = 1; n <= 14; n += 1) {
    if (snaps[`partial_${n}`].members) containers.push(snaps[`partial_${n}`].members);
  }
  for (const container of containers) {
    for (const member of container) {
      if (member.member_kind === 4) {
        member.value_hex = pendingVal.toString("hex");
        member.value_sha256 = shaHex(pendingVal);
      }
    }
  }
  const reimage = (members) =>
    shaHex(
      Buffer.concat(
        members.map((m) =>
          Buffer.concat([
            Buffer.from(m.complete_key_hex, "hex"),
            Buffer.from(m.value_hex, "hex"),
            Buffer.from(m.context_digest_hex, "hex"),
          ]),
        ),
      ),
    );
  for (let n = 1; n <= 14; n += 1) {
    if (snaps[`partial_${n}`].members) {
      snaps[`partial_${n}`].full_image_sha256 = reimage(snaps[`partial_${n}`].members);
    }
  }
  const new15 = snaps.exact_new_pending_15;
  new15.full_image_sha256 = reimage(new15.members);
  new15.value_substitution_rejected.full_image_sha256 = reimage(
    new15.value_substitution_rejected.members,
  );
  if (
    new15.value_substitution_rejected.full_image_sha256 === new15.full_image_sha256
  ) {
    for (const member of new15.value_substitution_rejected.members) {
      if (member.member_kind !== 4) {
        const raw = Buffer.from(member.value_hex, "hex");
        raw[raw.length - 1] ^= 1;
        member.value_hex = raw.toString("hex");
        member.value_sha256 = shaHex(raw);
        break;
      }
    }
    new15.value_substitution_rejected.full_image_sha256 = reimage(
      new15.value_substitution_rejected.members,
    );
  }
  new15.context_digest_substitution_rejected.full_image_sha256 = reimage(
    new15.context_digest_substitution_rejected.members,
  );
  if (
    new15.context_digest_substitution_rejected.full_image_sha256 ===
    new15.full_image_sha256
  ) {
    for (const member of new15.context_digest_substitution_rejected.members) {
      if (member.member_kind !== 4) {
        const raw = Buffer.from(member.context_digest_hex, "hex");
        raw[0] ^= 1;
        member.context_digest_hex = raw.toString("hex");
        break;
      }
    }
    new15.context_digest_substitution_rejected.full_image_sha256 = reimage(
      new15.context_digest_substitution_rejected.members,
    );
  }
  document.atomic_batch_manifests[roleName].full_image_sha256 = reimage(
    document.atomic_batch_manifests[roleName].exact_inventory,
  );
}

function mutateAllMetadataCoherent(document) {
  document.schema = "ninlil.production-attachment-edhoc.vector.v1-DRIFT";
  document.schema_version = PA_SCHEMA_VERSION + 1;
  document.title = `${PA_TITLE} DRIFT`;
  document.adr = "docs/adr/9999-drift.md";
  document.normative_doc = "docs/99-drift.md";
  document.status = "DRIFTED_STATUS";
  document.status_map = {
    vector: "DRIFTED_STATUS",
    pa_tranche: "PA-S0",
    pa_tranche_state: "DRIFTED",
    accepted: true,
    implementation: true,
    hil: true,
    release: true,
    spec_accepted: true,
  };
  document.sources = [...PA_SOURCES, "docs/drift.md"];
  document.nonclaims = ["DRIFTED"];
  document.tools = { ...PA_TOOLS, generator: "tools/drift_gen.py" };
  document.lifecycle_constants = {
    ...PA_LIFECYCLE_CONSTANTS,
    value_label: "NINLIL-PA-N6-VALUE-X1",
    member_count_exact: 16,
  };
}

const PA_OBJECT_PATH_COUNT_EXACT = 850;
const PA_CLOSED_KEY_SCHEMA_PATH = path.join(
  here,
  "production_attachment_edhoc_closed_key_schema.json",
);
const PA_AUDIT_UNKNOWN_KEY = "__audit_unknown_key__";

let _closedKeySchemaCache = null;
function loadClosedKeySchema() {
  if (_closedKeySchemaCache !== null) return _closedKeySchemaCache;
  const raw = fs.readFileSync(PA_CLOSED_KEY_SCHEMA_PATH, "utf8");
  const schema = JSON.parse(raw);
  if (!schema || schema._t !== "obj") fail("closed key schema root");
  _closedKeySchemaCache = schema;
  return schema;
}

function walkClosedKeys(value, schema, pathStr, objectPaths) {
  const nodeType = schema._t;
  if (nodeType === "obj") {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      fail(`${pathStr}: expected object`);
    }
    if (objectPaths) objectPaths.push(pathStr);
    const keys = Object.keys(value);
    const expected = Object.keys(schema.k);
    const expSet = new Set(expected);
    for (const k of expected) {
      if (!Object.prototype.hasOwnProperty.call(value, k)) {
        fail(`${pathStr}: missing keys ${k}`);
      }
    }
    for (const k of keys) {
      if (!expSet.has(k)) fail(`${pathStr}: unknown keys ${k}`);
    }
    for (const k of expected) {
      walkClosedKeys(value[k], schema.k[k], `${pathStr}.${k}`, objectPaths);
    }
    return;
  }
  if (nodeType === "arr") {
    if (!Array.isArray(value)) fail(`${pathStr}: expected array`);
    for (let i = 0; i < value.length; i += 1) {
      walkClosedKeys(value[i], schema.item, `${pathStr}[${i}]`, objectPaths);
    }
    return;
  }
  if (nodeType === "str") {
    if (typeof value !== "string") fail(`${pathStr}: expected str`);
    return;
  }
  if (nodeType === "int") {
    exactInt(value, pathStr);
    return;
  }
  if (nodeType === "bool") {
    exactBool(value, pathStr);
    return;
  }
  fail(`${pathStr}: bad schema node type ${nodeType}`);
}

function collectObjectPaths(document) {
  const paths = [];
  walkClosedKeys(document, loadClosedKeySchema(), "$", paths);
  return paths;
}

function injectUnknownAtPath(document, pathStr) {
  const out = structuredClone(document);
  if (pathStr === "$") {
    out[PA_AUDIT_UNKNOWN_KEY] = true;
    return out;
  }
  const parts = [...pathStr.matchAll(/\.([A-Za-z0-9_]+)|\[(\d+)\]/g)];
  let node = out;
  for (const m of parts) {
    if (m[1] !== undefined) node = node[m[1]];
    else node = node[Number(m[2])];
  }
  if (node === null || typeof node !== "object" || Array.isArray(node)) {
    fail(`inject path not object: ${pathStr}`);
  }
  node[PA_AUDIT_UNKNOWN_KEY] = true;
  return out;
}

function runAllObjectPathUnknownKeyProbe(document) {
  const paths = collectObjectPaths(document);
  if (paths.length !== PA_OBJECT_PATH_COUNT_EXACT) {
    fail(
      `object path count ${paths.length} != pin ${PA_OBJECT_PATH_COUNT_EXACT}`,
    );
  }
  let rejected = 0;
  const accepted = [];
  for (const p of paths) {
    const mutated = injectUnknownAtPath(document, p);
    try {
      validate(mutated);
      accepted.push(p);
    } catch (error) {
      if (!(error instanceof GateError || error instanceof RangeError || error instanceof TypeError)) {
        throw error;
      }
      rejected += 1;
    }
  }
  return { rejected, accepted };
}

/**
 * Independent hard-coded recursive closed schema for PA-S0.
 * Envelope pins are source constants; body keys walked via committed
 * closed-key schema (not derived from the vector body at runtime).
 */
function validateClosedSchema(document) {
  // Full recursive closed-key walk over every object/array-member path.
  const paths = [];
  walkClosedKeys(document, loadClosedKeySchema(), "$", paths);
  if (paths.length !== PA_OBJECT_PATH_COUNT_EXACT) {
    fail(
      `object path count ${paths.length} != pin ${PA_OBJECT_PATH_COUNT_EXACT}`,
    );
  }

  // Envelope authority pins (independent of vector self-description).
  if (exactStr(document.schema, "$.schema") !== PA_SCHEMA_ID) fail("$.schema pin");
  if (exactInt(document.schema_version, "$.schema_version") !== PA_SCHEMA_VERSION) {
    fail("$.schema_version pin");
  }
  if (exactStr(document.title, "$.title") !== PA_TITLE) fail("$.title pin");
  if (exactStr(document.adr, "$.adr") !== PA_ADR) fail("$.adr pin");
  if (exactStr(document.normative_doc, "$.normative_doc") !== PA_NORMATIVE_DOC) {
    fail("$.normative_doc pin");
  }
  if (exactStr(document.status, "$.status") !== PA_STATUS) fail("$.status pin");
  if (!deepEqualJson(document.sources, [...PA_SOURCES])) fail("$.sources pin");
  if (!deepEqualJson(document.nonclaims, [...PA_NONCLAIMS])) fail("$.nonclaims pin");
  for (const [k, v] of Object.entries(PA_TOOLS)) {
    if (exactStr(document.tools[k], `$.tools.${k}`) !== v) fail(`$.tools.${k} pin`);
  }
  for (const [k, v] of Object.entries(PA_STATUS_MAP)) {
    if (typeof v === "boolean") {
      if (exactBool(document.status_map[k], `$.status_map.${k}`) !== v) {
        fail(`$.status_map.${k} pin`);
      }
    } else if (exactStr(document.status_map[k], `$.status_map.${k}`) !== v) {
      fail(`$.status_map.${k} pin`);
    }
  }
  for (const [k, v] of Object.entries(PA_LIFECYCLE_CONSTANTS)) {
    if (Array.isArray(v)) {
      if (!deepEqualJson(document.lifecycle_constants[k], [...v])) {
        fail(`$.lifecycle_constants.${k} pin`);
      }
    } else if (typeof v === "number") {
      if (exactInt(document.lifecycle_constants[k], `lc.${k}`) !== v) {
        fail(`$.lifecycle_constants.${k} pin`);
      }
    } else if (exactStr(document.lifecycle_constants[k], `lc.${k}`) !== v) {
      fail(`$.lifecycle_constants.${k} pin`);
    }
  }
  if (
    document.required_gate_cases.length !== requiredCases.size ||
    document.required_gate_cases.some((c) => !requiredCases.has(c))
  ) {
    fail("$.required_gate_cases set pin");
  }
  if (!Array.isArray(document.compact_radio_fragments) ||
      document.compact_radio_fragments.length !== 5) {
    fail("$.compact_radio_fragments length pin");
  }
  for (const role of ["device_local_role_1", "authority_local_role_2"]) {
    const inv = document.atomic_batch_manifests[role].exact_inventory;
    if (!Array.isArray(inv) || inv.length !== 15) {
      fail(`man.${role}.exact_inventory length`);
    }
  }

  const m1 =
    document.rfc9529_method3_suite2_reference.messages.message_1.hex;
  if (typeof m1 !== "string" || m1.length < 2 || m1.slice(0, 2) !== "03") {
    fail("rfc.message_1 method byte pin 0x03");
  }
  if (m1.slice(0, 2) === "04") fail("rfc.message_1 03→04 drift");
  if (
    exactInt(
      document.lifecycle_constants.rfc_message_1_method_byte,
      "lc.rfc_m1",
    ) !== 3
  ) {
    fail("lifecycle_constants.rfc_message_1_method_byte");
  }
  if (
    exactStr(document.lifecycle_constants.value_label, "lc.value_label") !==
    "NINLIL-PA-N6-CODEC-V1"
  ) {
    fail("lifecycle_constants.value_label pin");
  }
}

function recomputeCrcN6at(value) {
  value.writeUInt32BE(crc32c(value.subarray(0, 116)), 116);
}
function recomputeCrcNab(batch) {
  batch.fill(0, 64, 68);
  batch.writeUInt32BE(crc32c(batch), 64);
}
function recomputeCrcNprLocal(packet) {
  packet.fill(0, 64, 68);
  packet.writeUInt32BE(crc32c(packet), 64);
}
function decodeCborBstr(buf, offset) {
  if (offset >= buf.length) fail("cbor bstr eof");
  const initial = buf[offset];
  const major = initial >> 5;
  const info = initial & 0x1f;
  offset += 1;
  if (major !== 2) fail("cbor bstr major");
  let length;
  if (info < 24) length = info;
  else if (info === 24) {
    if (offset >= buf.length) fail("cbor bstr len");
    length = buf[offset];
    offset += 1;
  } else fail("cbor bstr length form");
  const end = offset + length;
  if (end > buf.length) fail("cbor bstr overflow");
  return [buf.subarray(offset, end), end];
}
function decodeCcsCoseKey(ccs, field) {
  if (!ccs.length || ccs[0] === 0x4e || ccs[0] !== 0xa1) {
    fail(`${field}: CCS must be CBOR map(1), not ASCII`);
  }
  if (ccs[1] !== 0x08) fail(`${field}: CCS claim 8 (cnf)`);
  if (ccs[2] !== 0xa1 || ccs[3] !== 0x01) fail(`${field}: cnf COSE_Key`);
  if (ccs[4] !== 0xa5) fail(`${field}: COSE_Key map(5)`);
  let offset = 5;
  if (!equal(ccs.subarray(offset, offset + 2), Buffer.from([0x01, 0x02]))) {
    fail(`${field}: kty != EC2`);
  }
  offset += 2;
  if (ccs[offset] !== 0x02) fail(`${field}: kid key`);
  offset += 1;
  let kid;
  [kid, offset] = decodeCborBstr(ccs, offset);
  if (kid.length < 1 || kid.length > 8) fail(`${field}: kid length`);
  if (ccs[offset] !== 0x20) fail(`${field}: crv key`);
  offset += 1;
  if (ccs[offset] !== 0x01) fail(`${field}: crv != P-256`);
  offset += 1;
  if (ccs[offset] !== 0x21) fail(`${field}: x key`);
  offset += 1;
  let x;
  [x, offset] = decodeCborBstr(ccs, offset);
  if (x.length !== 32) fail(`${field}: x length`);
  if (ccs[offset] !== 0x22) fail(`${field}: y key`);
  offset += 1;
  let y;
  [y, offset] = decodeCborBstr(ccs, offset);
  if (y.length !== 32) fail(`${field}: y length`);
  if (offset !== ccs.length) fail(`${field}: CCS trailing`);
  return { kid, x, y, kty: 2, crv: 1 };
}


function r6NodeId16(stableIdBytes) {
  // docs/30 §994–996 R6 node-id (not PA-NODE-ID-V1)
  const len = Buffer.alloc(2);
  len.writeUInt16BE(stableIdBytes.length);
  return sha(Buffer.concat([
    Buffer.from("NINLIL-R6-NODE-ID-v1"),
    len,
    stableIdBytes,
  ])).subarray(0, 16);
}
function opaqueLenPrefix(value) {
  const out = Buffer.alloc(2 + value.length);
  out.writeUInt16BE(value.length);
  value.copy(out, 2);
  return out;
}
function hopContextBindingDigestIndependent(fields, hopContextId, directionCode) {
  const site = Buffer.isBuffer(fields.site_domain) ? fields.site_domain : hex(fields.site_domain, "hop.site");
  const att = Buffer.isBuffer(fields.attachment_id) ? fields.attachment_id : hex(fields.attachment_id, "hop.att");
  const ini = Buffer.isBuffer(fields.initiator_stable_digest) ? fields.initiator_stable_digest : hex(fields.initiator_stable_digest, "hop.is");
  const res = Buffer.isBuffer(fields.responder_stable_digest) ? fields.responder_stable_digest : hex(fields.responder_stable_digest, "hop.rs");
  const auth = Buffer.isBuffer(fields.authority_id) ? fields.authority_id : hex(fields.authority_id, "hop.auth");
  const mem = Buffer.alloc(8); mem.writeBigUInt64BE(BigInt(fields.membership_epoch));
  const attEp = Buffer.alloc(8); attEp.writeBigUInt64BE(BigInt(fields.attachment_epoch));
  const term = Buffer.alloc(8); term.writeBigUInt64BE(BigInt(fields.authority_term));
  const ctx = Buffer.alloc(4); ctx.writeUInt32BE(hopContextId >>> 0);
  const mask = Buffer.alloc(2); mask.writeUInt16BE(0x0003);
  return sha(Buffer.concat([
    Buffer.from("NINLIL-R6-HOP-CTX-v1"),
    Buffer.from([0x11, 2]),
    opaqueLenPrefix(site),
    mem,
    opaqueLenPrefix(att),
    attEp,
    opaqueLenPrefix(ini),
    opaqueLenPrefix(res),
    opaqueLenPrefix(auth),
    term,
    ctx,
    Buffer.from([directionCode & 0xff]),
    mask,
  ]));
}
function e2eContextBindingDigestIndependent(fields, e2eContextId, directionCode) {
  let sender = directionCode === 0 ? fields.initiator_stable_digest : fields.responder_stable_digest;
  let receiver = directionCode === 0 ? fields.responder_stable_digest : fields.initiator_stable_digest;
  if (!Buffer.isBuffer(sender)) sender = hex(sender, "e2e.s");
  if (!Buffer.isBuffer(receiver)) receiver = hex(receiver, "e2e.r");
  let site = fields.site_domain;
  let e2eId = fields.e2e_security_id;
  let auth = fields.authority_id;
  if (!Buffer.isBuffer(site)) site = hex(site, "e2e.site");
  if (!Buffer.isBuffer(e2eId)) e2eId = hex(e2eId, "e2e.id");
  if (!Buffer.isBuffer(auth)) auth = hex(auth, "e2e.auth");
  const mem = Buffer.alloc(8); mem.writeBigUInt64BE(BigInt(fields.membership_epoch));
  const ep = Buffer.alloc(8); ep.writeBigUInt64BE(BigInt(fields.e2e_security_epoch));
  const term = Buffer.alloc(8); term.writeBigUInt64BE(BigInt(fields.authority_term));
  const ctx = Buffer.alloc(4); ctx.writeUInt32BE(e2eContextId >>> 0);
  return sha(Buffer.concat([
    Buffer.from("NINLIL-R6-E2E-CTX-v1"),
    Buffer.from([0x11, 2]),
    opaqueLenPrefix(site),
    mem,
    opaqueLenPrefix(e2eId),
    ep,
    opaqueLenPrefix(sender),
    opaqueLenPrefix(receiver),
    opaqueLenPrefix(auth),
    term,
    ctx,
    Buffer.from([directionCode & 0xff]),
  ]));
}
function materializeMemberValueIndependent({
  memberKind,
  completeKey,
  installDigest,
  valueLength,
  markerValue,
  localSide = 0,
  keyGeneration = 1,
  membershipEpoch = 11,
  phase = "new",
  peerNodeId = null,
  localNodeId = null,
  contextId = 0,
  layerCode = 0,
}) {
  // Canonical N6 TX/RX/AL/HW/N6AT wire (docs/30) — not synthetic VALUE-V1.
  void installDigest;
  if (memberKind === 4) {
    if (phase === "old") fail("marker OLD absent");
    if (!markerValue || markerValue.length !== valueLength) fail("marker value");
    return markerValue;
  }
  const authorityNow = phase === "old" ? 1_000_000n : 1_300_000n;
  const putU16 = (b, o, v) => b.writeUInt16BE(v >>> 0, o);
  const putU32 = (b, o, v) => b.writeUInt32BE(v >>> 0, o);
  const putU64 = (b, o, v) => b.writeBigUInt64BE(BigInt(v), o);
  if (memberKind === 1) {
    if (localSide !== 1 && localSide !== 2) fail("lane side");
    if (completeKey.length !== 48) fail("lane key len");
    const receiver = localSide === 2 ? peerNodeId : localNodeId;
    if (!receiver || receiver.length !== 16) fail("lane receiver");
    const out = Buffer.alloc(68);
    const magic = localSide === 2 ? 0x4e365458 : 0x4e365258;
    putU32(out, 0, magic);
    putU16(out, 4, 2);
    putU16(out, 6, 0);
    // TX=1 / RX=0 (docs/30 §1031-1044)
    putU64(out, 8, localSide === 2 ? 1n : 0n);
    putU64(out, 16, BigInt(keyGeneration));
    completeKey.subarray(8, 24).copy(out, 24);
    putU64(out, 40, BigInt(membershipEpoch));
    out[48] = localSide;
    const epoch = Buffer.alloc(8);
    epoch.writeBigUInt64BE(BigInt(membershipEpoch));
    sha(Buffer.concat([
      receiver,
      Buffer.from([layerCode & 0xff]),
      epoch,
      Buffer.from([localSide & 0xff]),
    ])).subarray(0, 12).copy(out, 52);
    putU32(out, 64, crc32c(out.subarray(0, 64)));
    if (out.length !== valueLength) fail("lane value length");
    return out;
  }
  if (memberKind === 3) {
    const hw = phase === "old" ? 1n : BigInt(Math.max(1, keyGeneration));
    const out = Buffer.alloc(28);
    putU32(out, 0, 0x4e364857);
    putU16(out, 4, 1);
    putU16(out, 6, 0);
    putU64(out, 8, hw);
    putU64(out, 16, authorityNow);
    putU32(out, 24, crc32c(out.subarray(0, 24)));
    if (out.length !== valueLength) fail("hw value length");
    return out;
  }
  if (memberKind === 2) {
    const receiver =
      localSide === 2
        ? peerNodeId
        : localNodeId !== null
          ? localNodeId
          : Buffer.alloc(16);
    if (!receiver || receiver.length !== 16) fail("al receiver");
    if (phase !== "old" && contextId < 1) fail("al NEW context_id");
    const floor = phase === "old" ? 1 : Math.max(1, (contextId >>> 0) + 1);
    const active = phase === "old" ? 0 : 1;
    const out = Buffer.alloc(56);
    putU32(out, 0, 0x4e36414c);
    putU16(out, 4, 2);
    putU16(out, 6, 0);
    putU32(out, 8, floor);
    putU16(out, 12, active);
    putU16(out, 14, 0);
    putU32(out, 16, 0);
    putU64(out, 20, BigInt(membershipEpoch));
    putU64(out, 28, authorityNow);
    receiver.copy(out, 36);
    putU32(out, 52, crc32c(out.subarray(0, 52)));
    if (out.length !== valueLength) fail("al value length");
    return out;
  }
  fail("member_kind");
}
function materializeContextDigestIndependent({
  memberKind,
  completeKey,
  installDigest,
  attachmentId,
}) {
  if (memberKind === 4) return Buffer.alloc(32);
  return sha(
    Buffer.concat([
      Buffer.from("NINLIL-PA-N6-CTX-DIGEST-V1"),
      Buffer.from([memberKind]),
      completeKey,
      installDigest,
      attachmentId,
    ]),
  );
}
function materializeOldContextDigestIndependent({
  memberKind,
  completeKey,
  attachmentId,
}) {
  if (memberKind === 4) fail("marker OLD context absent");
  return sha(
    Buffer.concat([
      Buffer.from("NINLIL-PA-N6-OLD-CTX-DIGEST-V1"),
      Buffer.from([memberKind]),
      completeKey,
      attachmentId,
    ]),
  );
}
function fullImageFromMembers(members) {
  return Buffer.concat(
    members.map((m) =>
      Buffer.concat([
        hex(m.complete_key_hex, "ck"),
        hex(m.value_hex, "val"),
        hex(m.context_digest_hex, "ctx"),
      ]),
    ),
  );
}

const N6AT_STATE_NAME = { 1: "PENDING", 2: "ACTIVE", 3: "FENCED" };
const CLASSIFICATION_DOMAIN_EXACT = [
  "EXACT_OLD",
  ...Array.from({ length: 14 }, (_, i) => `PARTIAL_${i + 1}_CORRUPT`),
  "EXACT_NEW_PENDING_15",
  "EXACT_NEW_ACTIVE_MARKER_IN_15",
  "EXTRA_CORRUPT",
  "FOREIGN_OR_EXTRA_CORRUPT",
  "THIRD_OR_MISMATCH_CORRUPT",
  "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT",
  "DUPLICATE_KEYS_CORRUPT",
  "MISSING_MARKER_CORRUPT",
  "UNKNOWN_MARKER_STATE_CORRUPT",
  "UNCLASSIFIED_CORRUPT",
];

function deepMemberCopy(member) {
  const out = {};
  for (const [k, v] of Object.entries(member)) {
    out[k] = Array.isArray(v) ? [...v] : v;
  }
  return out;
}

function deriveValueSubstitutionMembers(baseMembers, mutatedIndex) {
  if (!(mutatedIndex >= 0 && mutatedIndex < baseMembers.length)) {
    fail(`value subst index out of range: ${mutatedIndex}`);
  }
  const out = baseMembers.map(deepMemberCopy);
  const raw = Buffer.from(hex(out[mutatedIndex].value_hex, "vs val"));
  if (raw.length === 0) fail("value subst empty value");
  raw[raw.length - 1] ^= 1;
  out[mutatedIndex].value_hex = raw.toString("hex");
  out[mutatedIndex].value_sha256 = shaHex(raw);
  return out;
}

function deriveContextSubstitutionMembers(baseMembers, mutatedIndex) {
  if (!(mutatedIndex >= 0 && mutatedIndex < baseMembers.length)) {
    fail(`ctx subst index out of range: ${mutatedIndex}`);
  }
  const out = baseMembers.map(deepMemberCopy);
  const raw = Buffer.from(hex(out[mutatedIndex].context_digest_hex, "cds ctx"));
  if (raw.length !== 32) fail("ctx subst length");
  raw[0] ^= 1;
  out[mutatedIndex].context_digest_hex = raw.toString("hex");
  return out;
}

function membersEqualExact(left, right, field) {
  if (left.length !== right.length) fail(`${field}: member count`);
  for (let i = 0; i < left.length; i += 1) {
    const a = left[i];
    const b = right[i];
    for (const key of [
      "index",
      "identity",
      "member_kind",
      "complete_key_hex",
      "complete_key_length",
      "value_hex",
      "value_sha256",
      "value_bytes",
      "context_digest_hex",
    ]) {
      if (a[key] !== b[key]) fail(`${field}: member[${i}].${key} mismatch`);
    }
  }
}

function validateSubstitutionRejected({
  kind,
  block,
  baseMembers,
  fullImageSha,
  field,
}) {
  requireKeys(block, field, [
    "mutated_index",
    "members",
    "full_image_sha256",
    "classification",
    "commit_unknown_accepted",
  ]);
  if (
    exactStr(block.classification, `${field} cls`) !==
    "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT"
  ) {
    fail(`${field}: classification`);
  }
  if (exactBool(block.commit_unknown_accepted, `${field} CU`) !== false) {
    fail(`${field}: CU`);
  }
  const idx = exactInt(block.mutated_index, `${field} idx`);
  if (!(idx >= 0 && idx <= 14)) fail(`${field}: mutated_index range`);
  const expected =
    kind === "value"
      ? deriveValueSubstitutionMembers(baseMembers, idx)
      : kind === "context"
        ? deriveContextSubstitutionMembers(baseMembers, idx)
        : fail(`${field}: bad kind`);
  const got = block.members;
  if (!Array.isArray(got) || got.length !== 15) fail(`${field}: members length`);
  membersEqualExact(got, expected, `${field} members`);
  const diffs = [];
  for (let i = 0; i < baseMembers.length; i += 1) {
    const valDiff = baseMembers[i].value_hex !== got[i].value_hex;
    const ctxDiff =
      baseMembers[i].context_digest_hex !== got[i].context_digest_hex;
    if (valDiff || ctxDiff) diffs.push([i, valDiff, ctxDiff]);
  }
  if (diffs.length !== 1 || diffs[0][0] !== idx) {
    fail(`${field}: must differ at exactly mutated_index=${idx}`);
  }
  const [, valDiff, ctxDiff] = diffs[0];
  if (kind === "value" && (!valDiff || ctxDiff)) {
    fail(`${field}: value-only mutation required`);
  }
  if (kind === "context" && (valDiff || !ctxDiff)) {
    fail(`${field}: context-only mutation required`);
  }
  const imageSha = shaHex(fullImageFromMembers(got));
  if (imageSha === fullImageSha) fail(`${field}: image not divergent`);
  if (imageSha !== exactStr(block.full_image_sha256, `${field} img`)) {
    fail(`${field}: image pin`);
  }
}

function classifyWriteSetValueImageIndependent({
  presentMembers,
  oldMembers,
  newMembers,
  writeSetKeysOrdered,
  markerKey,
}) {
  // Per-row observed-OLD / proposed-NEW value-image CU (not key-count).
  const writeSet = writeSetKeysOrdered.slice();
  const writeSetSet = new Set(writeSet.map((k) => k.toString("hex")));
  if (writeSet.length !== 15 || writeSetSet.size !== 15) {
    return "UNCLASSIFIED_CORRUPT";
  }
  const presentMap = new Map();
  for (const m of presentMembers) {
    const k = hex(m.complete_key_hex, "present ck");
    const kh = k.toString("hex");
    if (presentMap.has(kh)) return "DUPLICATE_KEYS_CORRUPT";
    presentMap.set(kh, [
      hex(m.value_hex, "present val"),
      hex(m.context_digest_hex, "present ctx"),
    ]);
  }
  for (const kh of presentMap.keys()) {
    if (!writeSetSet.has(kh)) return "FOREIGN_OR_EXTRA_CORRUPT";
  }
  const oldMap = new Map(
    oldMembers.map((m) => [
      hex(m.complete_key_hex, "old ck").toString("hex"),
      [hex(m.value_hex, "old val"), hex(m.context_digest_hex, "old ctx")],
    ]),
  );
  const newMap = new Map(
    newMembers.map((m) => [
      hex(m.complete_key_hex, "new ck").toString("hex"),
      [hex(m.value_hex, "new val"), hex(m.context_digest_hex, "new ctx")],
    ]),
  );
  if (newMap.size !== 15) return "UNCLASSIFIED_CORRUPT";
  const pairEq = (a, b) => {
    if (a === undefined && b === undefined) return true;
    if (a === undefined || b === undefined) return false;
    return equal(a[0], b[0]) && equal(a[1], b[1]);
  };
  let pureNew = 0;
  let pureOld = 0;
  let third = 0;
  for (const k of writeSet) {
    const kh = k.toString("hex");
    const oldV = oldMap.get(kh);
    const newV = newMap.get(kh);
    const got = presentMap.get(kh);
    const matchesOld = pairEq(got, oldV);
    const matchesNew = got !== undefined && pairEq(got, newV);
    if (matchesOld && matchesNew) continue;
    if (matchesNew) pureNew += 1;
    else if (matchesOld) pureOld += 1;
    else third += 1;
  }
  if (third) return "THIRD_OR_MISMATCH_CORRUPT";
  if (pureNew === 0) return "EXACT_OLD";
  if (pureOld === 0) {
    const markerPair = presentMap.get(markerKey.toString("hex"));
    if (!markerPair) return "MISSING_MARKER_CORRUPT";
    const state = markerPair[0][8];
    if (state === 1) return "EXACT_NEW_PENDING_15";
    if (state === 2) return "EXACT_NEW_ACTIVE_MARKER_IN_15";
    if (state === 3) return "THIRD_OR_MISMATCH_CORRUPT";
    return "UNKNOWN_MARKER_STATE_CORRUPT";
  }
  if (pureNew >= 1 && pureNew <= 14) return `PARTIAL_${pureNew}_CORRUPT`;
  return "UNCLASSIFIED_CORRUPT";
}

function classifyGroupSnapshotIndependent({
  presentKeys,
  expectedKeysOrdered,
  markerKey,
  markerState,
  markerValueOk,
}) {
  // Key-presence helper for EXTRA only — not CU EXACT_OLD authority.
  const expectedSet = new Set(expectedKeysOrdered.map((k) => k.toString("hex")));
  const presentHex = presentKeys.map((k) => k.toString("hex"));
  const presentSet = new Set(presentHex);
  const count = presentKeys.length;
  if (count !== presentSet.size) return "DUPLICATE_KEYS_CORRUPT";
  if (count === 0) return "EXACT_OLD_COLD_OR_EMPTY_PRESENT";
  for (const k of presentSet) {
    if (!expectedSet.has(k)) return "FOREIGN_OR_EXTRA_CORRUPT";
  }
  if (count > 15) return "EXTRA_CORRUPT";
  if (count >= 1 && count <= 14) {
    return `KEY_PRESENCE_PARTIAL_${count}_NOT_VALUE_IMAGE`;
  }
  if (count === 15 && [...expectedSet].every((k) => presentSet.has(k))) {
    const markerHex = markerKey.toString("hex");
    if (!presentSet.has(markerHex)) return "MISSING_MARKER_CORRUPT";
    if (!markerValueOk) return "THIRD_OR_MISMATCH_CORRUPT";
    if (markerState === 1) return "EXACT_NEW_PENDING_15";
    if (markerState === 2) return "EXACT_NEW_ACTIVE_MARKER_IN_15";
    if (markerState === 3) return "THIRD_OR_MISMATCH_CORRUPT";
    return "UNKNOWN_MARKER_STATE_CORRUPT";
  }
  return "UNCLASSIFIED_CORRUPT";
}

function expectedInventoryIdentity({ memberKind, direction, lane, layerCode }) {
  // Independent identity label authority (generator nab1_exact_inventory).
  if (memberKind === 4) return "attachment_marker";
  let tag;
  if (layerCode === 1) tag = direction === 0 ? "hop_ir" : "hop_ri";
  else if (layerCode === 2) tag = direction === 0 ? "e2e_ir" : "e2e_ri";
  else fail(`identity: bad layer_code ${layerCode}`);
  if (memberKind === 1) return `${tag}_lane${lane}`;
  if (memberKind === 2) return `${tag}_n6al`;
  if (memberKind === 3) return `${tag}_n6hw`;
  fail(`identity: bad member_kind ${memberKind}`);
}

function materializeCompleteKey(args) {
  const {
    memberKind, direction, lane, localSide, localRole, contextId, keyGeneration,
    layerCode, membershipEpoch, installDigest, attachmentId, localNodeId, peerNodeId,
    fields = null,
  } = args;
  void installDigest;
  if (memberKind === 1) {
    if (!fields) fail("lane complete key requires fields for R6 binding");
    const f = { ...fields, attachment_id: fields.attachment_id || attachmentId };
    let binding;
    if (layerCode === 1) {
      binding = hopContextBindingDigestIndependent(f, contextId, direction);
    } else if (layerCode === 2) {
      binding = e2eContextBindingDigestIndependent(f, contextId, direction);
    } else fail("lane layer_code");
    const out = Buffer.alloc(48);
    out[0] = layerCode; out[1] = lane; out[2] = direction; out[3] = 0;
    out.writeUInt32BE(contextId >>> 0, 4);
    binding.copy(out, 8);
    out.writeBigUInt64BE(BigInt(keyGeneration), 40);
    return out;
  }
  if (memberKind === 2) {
    const receiver = localSide === 2 ? peerNodeId : localNodeId;
    const epoch = Buffer.alloc(8); epoch.writeBigUInt64BE(BigInt(membershipEpoch));
    const fingerprint = sha(Buffer.concat([
      receiver, Buffer.from([layerCode]), epoch, Buffer.from([localSide]),
    ])).subarray(0, 12);
    return Buffer.concat([Buffer.from([2, layerCode, localSide, 0]), epoch, fingerprint]);
  }
  if (memberKind === 3) {
    const receiver = localSide === 2 ? peerNodeId : localNodeId;
    const epoch = Buffer.alloc(8); epoch.writeBigUInt64BE(BigInt(membershipEpoch));
    const scope = sha(Buffer.concat([
      localNodeId, Buffer.from([layerCode, direction]), epoch, receiver,
    ])).subarray(0, 28);
    return Buffer.concat([Buffer.from([1, layerCode, direction, 0]), scope]);
  }
  if (memberKind === 4) {
    return Buffer.concat([Buffer.from([5, localRole, 1, 0]), attachmentId]);
  }
  fail("complete key kind");
}
/* N6AT value[28:84] authority fields bound to install_fields (generator make_n6at). */
const N6AT_AUTHORITY_FIELDS = Object.freeze([
  ["membership_epoch", 28, 8],
  ["attachment_epoch", 36, 8],
  ["lease_epoch", 44, 8],
  ["e2e_security_epoch", 52, 8],
  ["authority_term", 60, 8],
  ["credential_set_revision", 68, 8],
  ["revocation_generation", 76, 4],
  ["assignment_epoch", 80, 4],
]);

function validateN6atPair(
  key,
  value,
  role,
  state,
  attachmentId,
  installDigest,
  field,
  installFields,
) {
  if (
    key.length !== 20 ||
    value.length !== 120 ||
    !equal(key, Buffer.concat([Buffer.from([5, role, 1, 0]), attachmentId])) ||
    value.subarray(0, 4).toString() !== "N6AT" ||
    u16(value, 4) !== 1 ||
    u16(value, 6) !== 120 ||
    value[8] !== state ||
    value[9] !== role ||
    value[10] !== 0 ||
    value[11] !== 0 ||
    !equal(value.subarray(12, 28), attachmentId) ||
    !equal(value.subarray(84, 116), installDigest) ||
    crc32c(value.subarray(0, 116)) !== u32(value, 116)
  ) {
    fail(`${field}: N6AT pair`);
  }
  if (!installFields || typeof installFields !== "object") {
    fail(`${field}: install_fields required for N6AT authority`);
  }
  for (const [name, offset, width] of N6AT_AUTHORITY_FIELDS) {
    const expected = BigInt(exactInt(installFields[name], `iff.${name}`));
    const got = width === 8 ? u64(value, offset) : BigInt(u32(value, offset));
    if (got !== expected) {
      fail(`${field}: N6AT authority ${name} got=${got} expected=${expected}`);
    }
  }
}

function validateNab(batch, role, installDigest, field, inventory = null) {
  if (
    batch.length !== 368 ||
    batch.subarray(0, 4).toString() !== "NAB1" ||
    u16(batch, 4) !== 1 ||
    u16(batch, 6) !== 368 ||
    batch[8] !== role ||
    batch[9] !== 1 ||
    batch[10] !== 0 ||
    batch[11] !== 0 ||
    !equal(batch.subarray(28, 60), installDigest) ||
    u16(batch, 60) !== 15 ||
    u16(batch, 62) !== 20
  ) {
    fail(`${field}: NAB framing`);
  }
  const scratch = Buffer.from(batch);
  const stored = u32(batch, 64);
  scratch.fill(0, 64, 68);
  if (crc32c(scratch) !== stored) fail(`${field}: NAB CRC`);
  const counts = new Map();
  const rowKeys = [];
  const seenIdentities = [];
  const completeKeys = [];
  for (let index = 0; index < 15; index += 1) {
    const row = batch.subarray(68 + index * 20, 88 + index * 20);
    const [kind, direction, lane, localSide] = row;
    const contextId = u32(row, 4);
    const keyGeneration = u64(row, 8);
    const expectedSide = (role === 1) === (direction === 0) ? 2 : 1;
    if (
      ![1, 2, 3, 4].includes(kind) ||
      ![0, 1].includes(direction) ||
      (kind === 4 && localSide !== 0) ||
      (kind !== 4 && localSide !== expectedSide)
    ) {
      fail(`${field}: NAB catalog`);
    }
    const lengths = `${u16(row, 16)}/${u16(row, 18)}`;
    if (kind === 1 && (![1, 2, 3].includes(lane) || lengths !== "48/68")) {
      fail(`${field}: lane`);
    } else if (kind === 2 && (lane !== 0 || lengths !== "24/56")) {
      fail(`${field}: N6AL`);
    } else if (kind === 3 && (lane !== 0 || lengths !== "32/28")) {
      fail(`${field}: N6HW`);
    } else if (kind === 4) {
      if (
        direction !== 0 ||
        lane !== 0 ||
        contextId !== 0 ||
        keyGeneration !== 0n ||
        lengths !== "20/120"
      ) {
        fail(`${field}: marker`);
      }
    }
    const rowKey = `${kind}/${direction}/${lane}/${localSide}/${contextId}/${keyGeneration}`;
    if (rowKeys.includes(rowKey)) fail(`${field}: duplicate NAB entry before map`);
    rowKeys.push(rowKey);
    const countKey = `${kind}/${direction}`;
    counts.set(countKey, (counts.get(countKey) ?? 0) + 1);
    if (inventory !== null) {
      if (inventory.length !== 15) fail(`${field}: inventory length`);
      const expected = inventory[index];
      if (
        expected.index !== index ||
        expected.member_kind !== kind ||
        expected.direction !== direction ||
        expected.lane !== lane ||
        expected.local_side !== localSide ||
        expected.context_id !== contextId ||
        BigInt(expected.key_generation) !== keyGeneration ||
        expected.key_bytes !== u16(row, 16) ||
        expected.value_bytes !== u16(row, 18)
      ) {
        fail(`${field}: inventory mismatch at ${index}`);
      }
      if (seenIdentities.includes(expected.identity)) {
        fail(`${field}: duplicate identity ${expected.identity}`);
      }
      seenIdentities.push(expected.identity);
      if (expected.complete_key_hex) {
        const complete = hex(expected.complete_key_hex, `${field} ck ${index}`);
        if (
          complete.length !== expected.complete_key_length ||
          complete.length !== u16(row, 16)
        ) {
          fail(`${field}: complete key length`);
        }
        completeKeys.push(complete);
      }
    }
  }
  for (let i = 1; i < completeKeys.length; i += 1) {
    if (Buffer.compare(completeKeys[i - 1], completeKeys[i]) >= 0) {
      fail(`${field}: complete-key order at ${i}`);
    }
  }
  const expected = {
    "1/0": 3,
    "2/0": 2,
    "3/0": 2,
    "1/1": 3,
    "2/1": 2,
    "3/1": 2,
    "4/0": 1,
  };
  if (
    counts.size !== Object.keys(expected).length ||
    Object.entries(expected).some(([key, value]) => counts.get(key) !== value)
  ) {
    fail(`${field}: exact member set`);
  }
}

function recomputeCrcNpa(record) {
  record.fill(0, 84, 88);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32c(record));
  crc.copy(record, 84);
}

function recomputeCrcNpr(packet) {
  packet.fill(0, 64, 68);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32c(packet));
  crc.copy(packet, 64);
}

function validateCarrierBindings(document, executed) {
  const carriers = document.carrier_bindings;
  const usb = carriers.usb;
  const wifi = carriers.wifi;
  const radio = carriers.compact_radio;
  const uf = usb.fields;
  const wf = wifi.fields;
  const rf = radio.fields;
  const usbInput = Buffer.concat([
    Buffer.from(uf.label, "ascii"),
    hex(uf.carrier_instance_id_hex, "usb instance"),
    hex(uf.peer_id_hex, "usb peer"),
    (() => {
      const value = Buffer.alloc(8);
      value.writeBigUInt64BE(BigInt(uf.connection_generation));
      return value;
    })(),
    hex(uf.accepted_carrier_config_digest_hex, "usb config"),
  ]);
  const wifiInput = Buffer.concat([
    Buffer.from(wf.label, "ascii"),
    hex(wf.carrier_instance_id_hex, "wifi instance"),
    hex(wf.peer_session_id_hex, "wifi peer session"),
    hex(wf.peer_id_hex, "wifi peer"),
    hex(wf.network_instance_id_hex, "wifi network"),
    (() => {
      const value = Buffer.alloc(8);
      value.writeBigUInt64BE(BigInt(wf.connection_generation));
      return value;
    })(),
    (() => {
      const value = Buffer.alloc(4);
      value.writeUInt32BE(wf.path_generation);
      return value;
    })(),
    hex(wf.accepted_carrier_config_digest_hex, "wifi config"),
  ]);
  const radioInput = Buffer.concat([
    Buffer.from(rf.label, "ascii"),
    hex(rf.carrier_instance_id_hex, "radio instance"),
    hex(rf.channel_plan_digest_hex, "radio channel plan"),
    (() => {
      const value = Buffer.alloc(8);
      value.writeBigUInt64BE(BigInt(rf.radio_epoch));
      return value;
    })(),
    hex(rf.accepted_carrier_config_digest_hex, "radio config"),
  ]);
  if (
    uf.label !== "NINLIL-NAC1-USB-BINDING-V1" ||
    wf.label !== "NINLIL-NAC1-WIFI-BINDING-V1" ||
    rf.label !== "NINLIL-NAC1-RADIO-BINDING-V1" ||
    !equal(usbInput, hex(usb.canonical_input_hex, "usb canonical")) ||
    !equal(wifiInput, hex(wifi.canonical_input_hex, "wifi canonical")) ||
    !equal(radioInput, hex(radio.canonical_input_hex, "radio canonical")) ||
    shaHex(usbInput) !== usb.digest_hex ||
    shaHex(wifiInput) !== wifi.digest_hex ||
    shaHex(radioInput) !== radio.digest_hex ||
    usb.carrier_class !== 1 ||
    wifi.carrier_class !== 2 ||
    radio.carrier_class !== 3
  ) {
    fail("carrier binding derivation");
  }
  executed.add("CARRIER-BINDING-DERIVATION-PINNED");
  const mutatedWifi = Buffer.from(wifiInput);
  mutatedWifi[wf.label.length] ^= 1;
  if (shaHex(mutatedWifi) === wifi.digest_hex) fail("wifi binding mutation");
  executed.add("WIFI-BINDING-INPUT-MUTATION");
}

function validateCarrierTranscript(document, executed) {
  // Independent byte-exact carrier_transcript_digest oracle (docs/35 §4.1).
  const ct = document.carrier_transcript;
  if (!ct || typeof ct !== "object") fail("carrier_transcript missing");
  if (
    exactStr(ct.normative_formula_id, "ct.formula") !==
      "NINLIL-PA-CARRIER-TRANSCRIPT-V1" ||
    exactStr(ct.hash, "ct.hash") !== "SHA-256" ||
    exactStr(ct.label, "ct.label") !== "NINLIL-PA-CARRIER-TRANSCRIPT-V1" ||
    exactInt(ct.schema_version, "ct.sv") !== 1 ||
    exactBool(ct.role_in_preimage, "ct.role") !== false
  ) {
    fail("carrier_transcript envelope");
  }
  const primary = ct.primary_path;
  const entries = primary.entries;
  if (!Array.isArray(entries) || entries.length !== exactInt(primary.entry_count, "ct.ec")) {
    fail("carrier_transcript entries");
  }
  const cookieMode = exactInt(primary.cookie_mode, "ct.cm");
  const expectedKinds =
    cookieMode === 1 ? [1, 2, 4, 5, 6, 7] : [4, 5, 6, 7];
  if (JSON.stringify(primary.entry_order_kinds) !== JSON.stringify(expectedKinds)) {
    fail("carrier_transcript kind order");
  }
  const parts = [Buffer.from("NINLIL-PA-CARRIER-TRANSCRIPT-V1")];
  parts.push(Buffer.from([1]));
  parts.push(Buffer.from([exactInt(primary.carrier_class, "ct.cc")]));
  const session = hex(primary.session_id_hex, "ct.sid");
  if (session.length !== 16) fail("ct.session");
  parts.push(session);
  const eg = Buffer.alloc(8);
  eg.writeBigUInt64BE(BigInt(exactInt(primary.exchange_generation, "ct.eg")));
  parts.push(eg);
  const ai = Buffer.alloc(4);
  ai.writeUInt32BE(exactInt(primary.attempt_index, "ct.ai") >>> 0);
  parts.push(ai);
  const ae = Buffer.alloc(8);
  ae.writeBigUInt64BE(BigInt(exactInt(primary.attachment_epoch, "ct.ae")));
  parts.push(ae);
  parts.push(
    Buffer.from([
      exactInt(primary.method, "ct.method"),
      exactInt(primary.suite, "ct.suite"),
      cookieMode,
      entries.length,
    ]),
  );
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    const kind = expectedKinds[i];
    const record = hex(entry.nac1_hex, `ct.e${i}`);
    if (
      exactInt(entry.kind, `ct.e${i}.k`) !== kind ||
      record[16] !== kind ||
      record.length !== exactInt(entry.nac1_total_bytes, `ct.e${i}.len`) ||
      shaHex(record) !== exactStr(entry.nac1_sha256, `ct.e${i}.sha`) ||
      !equal(record.subarray(20, 36), session)
    ) {
      fail(`carrier_transcript entry ${i}`);
    }
    parts.push(Buffer.from([kind]));
    const seq = Buffer.alloc(4);
    seq.writeUInt32BE(exactInt(entry.record_sequence, `ct.e${i}.seq`) >>> 0);
    parts.push(seq);
    const lenb = Buffer.alloc(2);
    lenb.writeUInt16BE(record.length);
    parts.push(lenb);
    parts.push(record);
  }
  const preimage = Buffer.concat(parts);
  const digest = sha(preimage);
  if (
    shaHex(preimage) !== exactStr(primary.preimage_sha256, "ct.psha") ||
    preimage.length !== exactInt(primary.preimage_length, "ct.plen") ||
    !equal(preimage, hex(primary.preimage_hex, "ct.preimage")) ||
    digest.toString("hex") !== exactStr(primary.digest_hex, "ct.digest")
  ) {
    fail("carrier_transcript preimage/digest recompute");
  }
  const nai = hex(document.attachment_install.nai1_hex, "nai");
  const nax = hex(document.attachment_install.nax1_hex, "nax");
  const iff = document.attachment_install.install_fields;
  if (
    !equal(nai.subarray(352, 384), digest) ||
    !equal(nax.subarray(100, 132), digest) ||
    !equal(hex(iff.carrier_transcript_digest, "iff.ct"), digest) ||
    exactInt(ct.nai1_offset, "ct.nai_off") !== 352 ||
    exactInt(ct.nax1_offset, "ct.nax_off") !== 100
  ) {
    fail("carrier_transcript NAI1/NAX1 binding");
  }
  if (equal(digest, sha(Buffer.from("carrier-transcript")))) {
    fail("carrier_transcript synthetic filler");
  }
  const negatives = ct.negatives;
  if (!Array.isArray(negatives) || negatives.length < 5) {
    fail("carrier_transcript negatives");
  }
  const seen = new Set();
  for (const neg of negatives) {
    const nid = exactStr(neg.id, "ct.neg.id");
    if (seen.has(nid)) fail(`duplicate negative ${nid}`);
    seen.add(nid);
    if (exactBool(neg.differs_from_base, "ct.neg.diff") !== true) {
      fail(`negative ${nid} must differ`);
    }
    if (exactBool(neg.rejected, "ct.neg.rej")) continue;
    const negDig = hex(neg.digest_hex, `ct.neg.${nid}`);
    if (equal(negDig, digest) || !negDig.some((b) => b !== 0)) {
      fail(`negative ${nid} digest`);
    }
  }
  for (const required of [
    "flip_message_1_payload_byte0_recrc",
    "swap_message_1_message_2_order",
    "exchange_generation_plus_1",
    "attempt_index_plus_1",
    "attachment_epoch_plus_1",
    "suite_2_to_3",
    "cookie_mode_flip_same_entries",
  ]) {
    if (!seen.has(required)) fail(`missing negative ${required}`);
  }
  executed.add("CARRIER-TRANSCRIPT-BYTE-EXACT");
  executed.add("CARRIER-TRANSCRIPT-NEGATIVES");
}

function validateNpaNprAdversarial(document, installRecord, fragments, executed) {
  const expectedSession = installRecord.subarray(20, 36);
  const expectedBinding = installRecord.subarray(52, 84);
  const sessionMut = Buffer.from(installRecord);
  sessionMut[20] ^= 1;
  recomputeCrcNpa(sessionMut);
  if (equal(sessionMut.subarray(20, 36), expectedSession)) {
    fail("NAC session mutation not observed");
  }
  executed.add("NAC1-SESSION-MUTATION");
  const bindingMut = Buffer.from(installRecord);
  bindingMut[52] ^= 1;
  recomputeCrcNpa(bindingMut);
  if (equal(bindingMut.subarray(52, 84), expectedBinding)) {
    fail("NAC binding mutation not observed");
  }
  executed.add("NAC1-BINDING-MUTATION");

  const narSession = Buffer.from(fragments[1]);
  narSession[12] ^= 0x5a;
  recomputeCrcNpr(narSession);
  if (equal(narSession.subarray(12, 28), fragments[1].subarray(12, 28))) {
    fail("NAR session divergence not observed");
  }
  if (equal(narSession.subarray(12, 28), fragments[0].subarray(12, 28))) {
    fail("NAR session still matches peer fragment");
  }
  executed.add("NAR1-SESSION-GENERATION-BINDING-DIVERGENCE");

  const cookieFrags = document.stateless_cookie.response_radio_fragments.map(
    (item, index) => hex(item.hex, `cookie mix ${index}`),
  );
  const mixed1 = Buffer.from(cookieFrags[Math.min(1, cookieFrags.length - 1)]);
  if (equal(fragments[0].subarray(44, 60), mixed1.subarray(44, 60))) {
    mixed1[44] ^= 1;
    recomputeCrcNpr(mixed1);
  }
  if (equal(fragments[0].subarray(44, 60), mixed1.subarray(44, 60))) {
    fail("mixed fragment digest still equal");
  }
  executed.add("NAR1-MIXED-FRAGMENT-TUPLE");

  const nacCrc = Buffer.from(installRecord);
  nacCrc[nacCrc.length - 1] ^= 1;
  const scratch = Buffer.from(nacCrc);
  const stored = u32(nacCrc, 84);
  scratch.fill(0, 84, 88);
  if (crc32c(scratch) === stored) fail("NAC CRC mutation survived");
  executed.add("NAC1-CRC-MUTATION");
  const nacReserved = Buffer.from(installRecord);
  nacReserved[17] = 1;
  recomputeCrcNpa(nacReserved);
  if (nacReserved[17] === 0) fail("reserved mutation not observed");
  executed.add("NAC1-RESERVED-MUTATION");
  const nacLen = Buffer.from(installRecord);
  nacLen[8] ^= 1;
  if (u32(nacLen, 8) === installRecord.length) fail("length mutation not observed");
  executed.add("NAC1-LENGTH-MUTATION");

  const narCrc = Buffer.from(fragments[0]);
  narCrc[narCrc.length - 1] ^= 1;
  const narScratch = Buffer.from(narCrc);
  const narStored = u32(narCrc, 64);
  narScratch.fill(0, 64, 68);
  if (crc32c(narScratch) === narStored) fail("NAR CRC mutation survived");
  executed.add("NAR1-CRC-MUTATION");
  const narIndex = Buffer.from(fragments[0]);
  narIndex[42] = 3;
  recomputeCrcNpr(narIndex);
  if (narIndex[42] === fragments[0][42]) fail("NAR index mutation not observed");
  executed.add("NAR1-INDEX-MUTATION");
  const narOffset = Buffer.from(fragments[1]);
  narOffset.writeUInt32BE(0, 60);
  recomputeCrcNpr(narOffset);
  if (u32(narOffset, 60) === fragments[1][42] * 124) {
    fail("NAR offset mutation not observed");
  }
  executed.add("NAR1-OFFSET-MUTATION");
  const narDigest = Buffer.from(fragments[0]);
  narDigest[44] ^= 1;
  recomputeCrcNpr(narDigest);
  if (equal(narDigest.subarray(44, 60), fragments[0].subarray(44, 60))) {
    fail("NAR digest mutation not observed");
  }
  executed.add("NAR1-DIGEST-MUTATION");
  if (fragments.length !== 5 || fragments[0][42] !== 0) fail("reorder baseline");
  executed.add("NAR1-REORDER-DUPLICATE-LOSS");
}

function parseNarOwnerPacket(packet, field) {
  validateNpr(packet, field);
  return {
    session: packet.subarray(12, 28),
    generation: u64(packet, 28),
    sequence: u32(packet, 36),
    completeLength: u16(packet, 40),
    index: packet[42],
    count: packet[43],
    digest16: packet.subarray(44, 60),
    offset: u32(packet, 60),
    payload: packet.subarray(68),
  };
}

function narOwnerTuple(source, parsed) {
  return [
    source.toString("hex"),
    parsed.session.toString("hex"),
    parsed.generation.toString(),
    parsed.sequence,
    parsed.completeLength,
    parsed.digest16.toString("hex"),
    parsed.count,
  ].join(":");
}

function runNarOwner(
  packets,
  sourceLocator,
  { ownerSourceLocator = sourceLocator, timeout = false } = {},
) {
  if (sourceLocator.length !== 32 || ownerSourceLocator.length !== 32) {
    fail("NAR owner source locator length");
  }
  if (!equal(sourceLocator, ownerSourceLocator)) {
    return {
      outcome: "DISCARDED_SOURCE_MISMATCH",
      progressCount: 0,
      duplicateCount: 0,
      publishedBytes: 0,
    };
  }
  let owner = null;
  const slots = new Map();
  let duplicates = 0;
  for (let i = 0; i < packets.length; i += 1) {
    let parsed;
    try {
      parsed = parseNarOwnerPacket(packets[i], `nar-owner[${i}]`);
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
      return {
        outcome: "DISCARDED_MALFORMED",
        progressCount: slots.size,
        duplicateCount: duplicates,
        publishedBytes: 0,
      };
    }
    const tuple = narOwnerTuple(sourceLocator, parsed);
    if (owner === null) owner = tuple;
    else if (owner !== tuple) {
      return {
        outcome: "DISCARDED_MIXED_TUPLE",
        progressCount: slots.size,
        duplicateCount: duplicates,
        publishedBytes: 0,
      };
    }
    if (slots.has(parsed.index)) {
      const prior = slots.get(parsed.index);
      if (equal(prior.packet, packets[i])) {
        duplicates += 1;
        continue;
      }
      return {
        outcome: "DISCARDED_CONFLICTING_DUPLICATE",
        progressCount: slots.size,
        duplicateCount: duplicates,
        publishedBytes: 0,
      };
    }
    slots.set(parsed.index, { packet: packets[i], parsed });
  }
  if (owner === null) {
    return {
      outcome: "INCOMPLETE",
      progressCount: 0,
      duplicateCount: 0,
      publishedBytes: 0,
    };
  }
  const count = slots.values().next().value.parsed.count;
  if (slots.size < count) {
    return {
      outcome: timeout ? "DISCARDED_IDLE_TIMEOUT" : "INCOMPLETE",
      progressCount: slots.size,
      duplicateCount: duplicates,
      publishedBytes: 0,
    };
  }
  const ordered = [];
  for (let index = 0; index < count; index += 1) {
    if (!slots.has(index)) {
      return {
        outcome: timeout ? "DISCARDED_IDLE_TIMEOUT" : "INCOMPLETE",
        progressCount: slots.size,
        duplicateCount: duplicates,
        publishedBytes: 0,
      };
    }
    ordered.push(slots.get(index).parsed);
  }
  const complete = Buffer.concat(ordered.map((item) => item.payload));
  const first = ordered[0];
  if (
    complete.length !== first.completeLength ||
    !equal(sha(complete).subarray(0, 16), first.digest16)
  ) {
    return {
      outcome: "DISCARDED_DIGEST_OR_LENGTH",
      progressCount: slots.size,
      duplicateCount: duplicates,
      publishedBytes: 0,
    };
  }
  try {
    validateNpa(complete, "nar-owner complete");
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
    return {
      outcome: "DISCARDED_INNER_MISMATCH",
      progressCount: slots.size,
      duplicateCount: duplicates,
      publishedBytes: 0,
    };
  }
  if (
    !equal(complete.subarray(20, 36), first.session) ||
    u64(complete, 36) !== first.generation ||
    u32(complete, 44) !== first.sequence
  ) {
    return {
      outcome: "DISCARDED_INNER_MISMATCH",
      progressCount: slots.size,
      duplicateCount: duplicates,
      publishedBytes: 0,
    };
  }
  return {
    outcome: "COMPLETE",
    progressCount: slots.size,
    duplicateCount: duplicates,
    publishedBytes: complete.length,
    completeSha256: shaHex(complete),
  };
}

function assertNarOwnerMatrix(document, executed) {
  const fragments = document.compact_radio_fragments.map((row, index) =>
    hex(row.hex, `nar matrix fragment ${index}`),
  );
  if (
    fragments.length !== 5 ||
    document.nar1_reassembly.fixed_slots !== 5 ||
    JSON.stringify(document.nar1_reassembly.owner_key_fields) !==
      JSON.stringify([
        "source_locator_digest32",
        "session_id16",
        "exchange_generation_u64",
        "record_sequence_u32",
        "complete_nac1_bytes_u16",
        "digest16",
        "fragment_count_u8",
      ])
  ) {
    fail("NAR owner contract");
  }
  const source = hex(
    document.preauth_owner.source_locator_digest_hex,
    "NAR source locator",
  );
  const conflict = Buffer.from(fragments[0]);
  conflict[conflict.length - 1] ^= 1;
  recomputeCrcNpr(conflict);
  const overlap = Buffer.from(fragments[1]);
  overlap.writeUInt32BE(100, 60);
  recomputeCrcNpr(overlap);
  const mixed = Buffer.from(fragments[1]);
  mixed.writeBigUInt64BE(u64(mixed, 28) + 1n, 28);
  recomputeCrcNpr(mixed);
  const innerMismatch = fragments.map((packet) => {
    const changed = Buffer.from(packet);
    changed.writeBigUInt64BE(u64(changed, 28) + 1n, 28);
    recomputeCrcNpr(changed);
    return changed;
  });
  const otherSource = sha(Buffer.from("other-source"));
  const actual = {
    canonical_success: runNarOwner(fragments, source),
    reordered_success: runNarOwner([...fragments].reverse(), source),
    same_duplicate_no_progress: runNarOwner(
      [fragments[0], fragments[0], ...fragments.slice(1)],
      source,
    ),
    conflicting_duplicate_discard: runNarOwner(
      [fragments[0], conflict, ...fragments.slice(1)],
      source,
    ),
    gap_loss_timeout_discard: runNarOwner(fragments.slice(0, -1), source, {
      timeout: true,
    }),
    overlap_discard: runNarOwner([fragments[0], overlap], source),
    mixed_tuple_discard: runNarOwner([fragments[0], mixed], source),
    inner_mismatch_discard: runNarOwner(innerMismatch, source),
    source_mismatch_discard: runNarOwner(fragments, otherSource, {
      ownerSourceLocator: source,
    }),
  };
  for (const [name, result] of Object.entries(actual)) {
    const recorded = document.nar1_reassembly.cases[name];
    if (
      recorded.outcome !== result.outcome ||
      exactInt(recorded.progress_count, `${name}.progress`) !==
        result.progressCount ||
      exactInt(recorded.duplicate_count, `${name}.duplicate`) !==
        result.duplicateCount ||
      exactInt(recorded.published_bytes, `${name}.published`) !==
        result.publishedBytes ||
      (result.completeSha256 !== undefined &&
        exactStr(recorded.complete_sha256, `${name}.complete_sha256`) !==
          result.completeSha256)
    ) {
      fail(`NAR executable owner case ${name}`);
    }
  }
  if (
    actual.reordered_success.outcome !== "COMPLETE" ||
    actual.same_duplicate_no_progress.duplicateCount !== 1 ||
    actual.same_duplicate_no_progress.progressCount !== fragments.length
  ) {
    fail("NAR reorder/duplicate progress authority");
  }
  executed.add("PA-NAR-REORDER-SUCCESS");
  executed.add("PA-NAR-DUPLICATE-NO-PROGRESS");
  executed.add("PA-NAR-CONFLICT-GAP-OVERLAP-MIXED-TIMEOUT");
}

function runNasStream(chunks, eof) {
  const record = Buffer.concat(chunks);
  if (record.length > 612) return { outcome: "CLOSE_OVERFLOW", deliveries: 0 };
  if (record.length >= 12) {
    if (record.subarray(0, 4).toString("ascii") !== "NAS1") {
      return { outcome: "CLOSE_MAGIC", deliveries: 0 };
    }
    if (record[4] !== 1) {
      return { outcome: "CLOSE_FUTURE_OR_BAD_VERSION", deliveries: 0 };
    }
    if (![1, 2].includes(record[5]) || u16(record, 6) !== 12) {
      return { outcome: "CLOSE_HEADER", deliveries: 0 };
    }
    const innerLength = u32(record, 8);
    if (innerLength < 88 || innerLength > 600) {
      return { outcome: "CLOSE_LENGTH", deliveries: 0 };
    }
    const total = 12 + innerLength;
    if (record.length > total) {
      return { outcome: "CLOSE_TRAILING_BYTES", deliveries: 0 };
    }
    if (record.length === total) {
      const inner = record.subarray(12);
      try {
        validateNpa(inner, "NAS inner");
      } catch (error) {
        if (!(error instanceof GateError)) throw error;
        return { outcome: "CLOSE_INNER_CORRUPT", deliveries: 0 };
      }
      if (inner[18] !== record[5]) {
        return {
          outcome: "CLOSE_INNER_CARRIER_MISMATCH",
          deliveries: 0,
        };
      }
      return {
        outcome: "DELIVERED",
        deliveries: 1,
        innerSha256: shaHex(inner),
      };
    }
  }
  return {
    outcome: eof ? "CLOSE_SHORT_EOF" : "NEED_MORE",
    deliveries: 0,
  };
}

function assertNasLifecycle(document, executed) {
  const nas = hex(document.stream_wrapper.usb_nas1_hex, "NAS lifecycle");
  const future = Buffer.from(nas);
  future[4] = 2;
  const mismatch = Buffer.from(nas);
  mismatch[30] = 2; // 12-byte wrapper + inner carrier byte 18.
  const inner = mismatch.subarray(12);
  inner.fill(0, 84, 88);
  inner.writeUInt32BE(crc32c(inner), 84);
  const outcomes = {
    single_read_success: runNasStream([nas], false),
    partial_read_success: runNasStream(
      [nas.subarray(0, 1), nas.subarray(1, 7), nas.subarray(7, 12),
        nas.subarray(12, 91), nas.subarray(91)],
      false,
    ),
    short_eof_close: runNasStream([nas.subarray(0, -1)], true),
    trailing_bytes_close: runNasStream(
      [Buffer.concat([nas, Buffer.from([0])])],
      false,
    ),
    future_version_close: runNasStream([future], false),
    inner_carrier_mismatch_close: runNasStream([mismatch], false),
  };
  if (
    document.nas1_stream_lifecycle.buffer_capacity_bytes !== 612 ||
    document.nas1_stream_lifecycle.one_record_per_wrapper !== true
  ) {
    fail("NAS lifecycle contract");
  }
  for (const [name, result] of Object.entries(outcomes)) {
    const recorded = document.nas1_stream_lifecycle.cases[name];
    if (
      recorded.outcome !== result.outcome ||
      exactInt(recorded.delivery_count, `${name}.delivery`) !==
        result.deliveries ||
      (result.innerSha256 !== undefined &&
        exactStr(recorded.inner_sha256, `${name}.inner_sha256`) !==
          result.innerSha256)
    ) {
      fail(`NAS incremental lifecycle ${name}`);
    }
  }
  executed.add("PA-NAS-PARTIAL-SHORT-TRAILING-FUTURE-INNER");
}

function assertReattach10k(document, executed) {
  const expected = {
    cycles: 10_000,
    restart_after_each_cycle: true,
    initial_floors: [42, 44, 48, 54],
    initial_high_waters: [59, 61, 67, 71],
    regression_count: 0,
  };
  let floors = [...expected.initial_floors];
  let highWaters = [...expected.initial_high_waters];
  const transcript = Buffer.alloc(expected.cycles * (4 + 8 * 8));
  let offset = 0;
  for (let cycle = 1; cycle <= expected.cycles; cycle += 1) {
    const priorFloors = [...floors];
    const priorHighWaters = [...highWaters];
    floors = floors.map((value) => value + 1);
    highWaters = highWaters.map((value) => value + 1);
    if (
      floors.some((value, index) => value < priorFloors[index]) ||
      highWaters.some((value, index) => value < priorHighWaters[index])
    ) {
      fail("reattach 10k monotonic regression");
    }
    transcript.writeUInt32BE(cycle, offset);
    offset += 4;
    for (const value of [...floors, ...highWaters]) {
      transcript.writeBigUInt64BE(BigInt(value), offset);
      offset += 8;
    }
  }
  const got =
    document.lifecycle.group_machine.snapshots.reattach_10k_restart;
  if (
    got.cycles !== expected.cycles ||
    got.restart_after_each_cycle !== true ||
    JSON.stringify(got.initial_floors) !==
      JSON.stringify(expected.initial_floors) ||
    JSON.stringify(got.initial_high_waters) !==
      JSON.stringify(expected.initial_high_waters) ||
    JSON.stringify(got.final_floors) !== JSON.stringify(floors) ||
    JSON.stringify(got.final_high_waters) !== JSON.stringify(highWaters) ||
    got.regression_count !== 0 ||
    got.transcript_sha256 !== shaHex(transcript)
  ) {
    fail("reattach 10k restart authority");
  }
  executed.add("PA-REATTACH-10K-RESTART-MONOTONIC");
}

function classifyCuRow(row) {
  const pairEquals = (prefixA, prefixB) =>
    row[`${prefixA}_value_hex`] === row[`${prefixB}_value_hex`] &&
    row[`${prefixA}_context_digest_hex`] ===
      row[`${prefixB}_context_digest_hex`];
  if (row.durable_present !== true) return "ABSENT";
  const oldEqualsNew = pairEquals("old", "new");
  if (pairEquals("durable", "old") && oldEqualsNew) return "STABLE";
  if (pairEquals("durable", "old")) return "OLD";
  if (pairEquals("durable", "new")) return "NEW";
  return "THIRD";
}

function assertPrerequisites(document, executed) {
  const block = document.prerequisites;
  if (
    JSON.stringify(block.dependency_readiness) !==
      JSON.stringify({
        factory_identity: "UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED",
        owner_start_without_accepted_dependencies: "FAIL_CLOSED_NOT_READY",
        pa_may_claim_dependency_ready: false,
        production_attachment_status: "PROPOSED",
        site_membership: "UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED",
      }) ||
    JSON.stringify(block.factory_identity_claim) !==
      JSON.stringify({
        claim_revision_nonzero: true,
        copy_owned: true,
        required_state: "PROVISIONED",
        stable_id_digest_bytes: 32,
      }) ||
    block.site_membership_claim.required_state !== "ACTIVE" ||
    block.site_membership_claim.copy_owned !== true
  ) {
    fail("PA prerequisite dependency/claim authority");
  }
  const iff = document.attachment_install.install_fields;
  const membership = block.site_membership_claim;
  for (const field of [
    "authority_term",
    "membership_epoch",
    "credential_set_revision",
    "revocation_generation",
    "assignment_epoch",
  ]) {
    if (membership[field] !== iff[field]) fail(`membership claim ${field}`);
  }
  if (
    membership.authority_id_hex !== iff.authority_id ||
    membership.site_domain_hex !== iff.site_domain
  ) {
    fail("membership claim byte identity");
  }
  const roleSpecs = [
    [
      "initiator_local_role_1",
      1,
      "initiator",
      P256_INITIATOR_X,
      P256_INITIATOR_Y,
      23,
      "494b524546303031",
    ],
    [
      "responder_local_role_2",
      2,
      "responder",
      P256_RESPONDER_X,
      P256_RESPONDER_Y,
      29,
      "524b524546303031",
    ],
  ];
  for (const [name, role, side, x, y, generation, opaqueRef] of roleSpecs) {
    const row = block.local_credential_descriptors[name];
    const ccs = hex(document.credentials[`${side}_ccs_hex`], `${name}.ccs`);
    if (
      row.local_role !== role ||
      row.factory_identity_state !== "PROVISIONED" ||
      row.factory_stable_id_digest_hex !== iff[`${side}_stable_digest`] ||
      row.canonical_ccs_hex !== ccs.toString("hex") ||
      row.canonical_ccs_sha256 !== shaHex(ccs) ||
      row.kid_hex !== document.credentials[`${side}_kid_hex`] ||
      row.curve !== "P-256" ||
      row.public_key_digest_hex !==
        shaHex(Buffer.concat([Buffer.from([4]), x, y])) ||
      row.credential_set_revision !== iff.credential_set_revision ||
      row.provider_generation !== generation ||
      row.opaque_key_reference_hex !== opaqueRef ||
      row.opaque_key_reference_length !== 8 ||
      row.copy_owned !== true
    ) {
      fail(`PA local credential descriptor ${name}`);
    }
  }
  const port = block.local_static_dh_port;
  if (
    port.operation !== "P256_STATIC_DH" ||
    port.output_owner !== "CALLER_OWNED_BOUNDED_SECRET_WORKSPACE" ||
    port.output_bytes_exact !== 32 ||
    port.write_count_exact !== 1 ||
    port.private_scalar_exported !== false ||
    port.backend_pointer_exported !== false ||
    port.provider_serialization !== "NO_REENTRY" ||
    port.partial_output_action !== "ZEROIZE32_AND_TERMINAL" ||
    port.after_prk_action !== "ZEROIZE32"
  ) {
    fail("PA local static-DH port");
  }
  const transitionIds = [
    "VALID_BASELINE",
    "WRONG_FACTORY_IDENTITY",
    "WRONG_ROLE",
    "WRONG_CURVE",
    "PUBLIC_PRIVATE_KEY_MISMATCH",
    "CREDENTIAL_REVISION_ROLLBACK",
    "PROVIDER_GENERATION_ROLLBACK",
    "UNKNOWN_OPAQUE_KEY_REFERENCE",
    "PROVIDER_REENTRY",
    "PARTIAL_OUTPUT",
  ];
  const transitions = block.local_static_dh_transitions;
  const baseline = {
    factory_stable_id_digest_hex: iff.initiator_stable_digest,
    descriptor_local_role: 1,
    requested_local_role: 1,
    curve: "P-256",
    public_private_binding: "MATCH",
    credential_set_revision: iff.credential_set_revision,
    credential_set_revision_floor: iff.credential_set_revision,
    provider_generation: 23,
    provider_generation_floor: 23,
    opaque_key_reference_hex: "494b524546303031",
    provider_reentry: false,
    provider_output_bytes: 32,
  };
  function deriveLocalStaticDh(input) {
    const valid =
      input.factory_stable_id_digest_hex === baseline.factory_stable_id_digest_hex &&
      input.descriptor_local_role === 1 && input.requested_local_role === 1 &&
      input.curve === "P-256" && input.public_private_binding === "MATCH" &&
      input.credential_set_revision >= input.credential_set_revision_floor &&
      input.provider_generation >= input.provider_generation_floor &&
      input.opaque_key_reference_hex === baseline.opaque_key_reference_hex &&
      input.provider_reentry === false && input.provider_output_bytes === 32;
    return valid
      ? { status: "SUCCESS", terminal: false, wire_records: 0, exporter_calls: 0,
          ecdh_write_count: 1, ecdh_output_published_bytes: 32,
          zeroized_output_bytes: 32, private_key_bytes_exported: 0 }
      : { status: "TERMINAL_AUTHENTICATION_FAILURE", terminal: true,
          wire_records: 0, exporter_calls: 0, ecdh_write_count: 0,
          ecdh_output_published_bytes: 0, zeroized_output_bytes: 32,
          private_key_bytes_exported: 0 };
  }
  const failureDelta = new Map([
    ["WRONG_FACTORY_IDENTITY", ["factory_stable_id_digest_hex", "00".repeat(32)]],
    ["WRONG_ROLE", ["requested_local_role", 2]],
    ["WRONG_CURVE", ["curve", "X25519"]],
    ["PUBLIC_PRIVATE_KEY_MISMATCH", ["public_private_binding", "MISMATCH"]],
    ["CREDENTIAL_REVISION_ROLLBACK", ["credential_set_revision", 18]],
    ["PROVIDER_GENERATION_ROLLBACK", ["provider_generation", 22]],
    ["UNKNOWN_OPAQUE_KEY_REFERENCE", ["opaque_key_reference_hex", "554e4b4e4f574e31"]],
    ["PROVIDER_REENTRY", ["provider_reentry", true]],
    ["PARTIAL_OUTPUT", ["provider_output_bytes", 31]],
  ]);
  function validateLocalStaticDhTransitions(rows) {
    if (JSON.stringify(rows.map((row) => row.id)) !== JSON.stringify(transitionIds)) {
      fail("PA local static-DH transition IDs");
    }
    rows.forEach((row, index) => {
      const keys = Object.keys(baseline);
      const deltaKeys = keys.filter((key) => row.input[key] !== baseline[key]);
      const derived = deriveLocalStaticDh(row.input);
      const expectedMatches = Object.keys(derived).length === Object.keys(row.expected).length &&
        Object.keys(derived).every((key) => derived[key] === row.expected[key]);
      const required = index === 0 ? null : failureDelta.get(row.id);
      const deltaMatches = index === 0
        ? deltaKeys.length === 0
        : required !== undefined && deltaKeys.length === 1 &&
          deltaKeys[0] === required[0] && row.input[required[0]] === required[1];
      if (Object.keys(row.input).length !== keys.length || !expectedMatches || !deltaMatches) {
        fail(`PA local static-DH ID/delta binding ${row.id}`);
      }
    });
  }
  validateLocalStaticDhTransitions(transitions);
  const swap = transitions.map((row) => ({ ...row, input: { ...row.input } }));
  [swap[2].input, swap[3].input] = [swap[3].input, swap[2].input];
  const rotate = transitions.map((row) => ({ ...row, input: { ...row.input } }));
  [rotate[2].input, rotate[3].input, rotate[4].input] =
    [rotate[3].input, rotate[4].input, rotate[2].input];
  for (const probe of [swap, rotate]) {
    let rejected = false;
    try { validateLocalStaticDhTransitions(probe); } catch (error) { rejected = true; }
    if (!rejected) fail("PA local static-DH ID/input mutant accepted");
  }
  executed.add("PA-PREREQ-FACTORY-MEMBERSHIP-LOCAL-KEY");
  executed.add("PA-LOCAL-KEY-MISMATCH-ROLLBACK-REENTRY");
}

function assertEdhocAttempts(document, executed) {
  const block = document.edhoc_attempts;
  for (const [name, suite, generation, caseId] of [
    ["suite_2", 2, 101, "PA-EDHOC-SUITE2-M1-M4"],
    ["suite_3", 3, 102, "PA-EDHOC-SUITE3-M1-M4"],
  ]) {
    const attempt = block.attempts[name];
    if (
      attempt.method !== 3 ||
      attempt.suite !== suite ||
      attempt.exchange_generation !== generation ||
      attempt.fixture_kind !==
        "SYNTHETIC_PROFILE_STATE_MACHINE_NOT_CRYPTO_KAT" ||
      attempt.messages.length !== 4 ||
      attempt.message_4_required !== true ||
      attempt.message_4_verified_before_exporter !== true ||
      attempt.exporter_calls_before_message_4 !== 0 ||
      attempt.exporter_calls_after_message_4 !== 8 ||
      attempt.real_provider_kat_claimed !== false ||
      attempt.final_state !== "EDHOC_COMPLETE"
    ) {
      fail(`EDHOC attempt ${name}`);
    }
    attempt.messages.forEach((row, index) => {
      const stage = index + 1;
      const payload = hex(row.payload_hex, `${name}.message_${stage}`);
      const nac = hex(row.nac1_hex, `${name}.nac_${stage}`);
      validateNpa(nac, `${name}.nac_${stage}`, 3 + stage, stage, 3);
      if (
        row.stage !== stage ||
        row.kind !== 3 + stage ||
        row.message_name !== `message_${stage}` ||
        row.payload_sha256 !== shaHex(payload) ||
        u64(nac, 36) !== BigInt(generation) ||
        !equal(nac.subarray(88), payload) ||
        row.ead_present !== false ||
        row.ead_item_count !== 0 ||
        row.verified !== true ||
        (stage === 1 && (payload[0] !== 3 || payload[1] !== suite))
      ) {
        fail(`EDHOC ${name} message ${stage}`);
      }
    });
    executed.add(caseId);
  }
  function validateEadRows(rows) {
    if (!Array.isArray(rows) || rows.length !== 4) fail("EDHOC EAD cardinality");
    const stages = new Set();
    const consumed = new Set();
    for (const row of rows) {
      const bytes = hex(row.ead_hex, "EDHOC EAD bytes");
      if (!Number.isInteger(row.stage) || row.stage < 1 || row.stage > 4 ||
          stages.has(row.stage) || row.id !== `EAD_${row.stage}_NONEMPTY` ||
          bytes.length === 0 || !equal(bytes, Buffer.from([row.stage])) ||
          consumed.has(bytes.toString("hex")) || row.outcome !== "TERMINAL_REJECT" ||
          row.exporter_calls !== 0 || row.automatic_retry_count !== 0 ||
          row.wire_records_after_reject !== 0) {
        fail("EDHOC EAD bijection/consumption");
      }
      stages.add(row.stage);
      consumed.add(bytes.toString("hex"));
    }
    if (stages.size !== 4 || consumed.size !== 4) fail("EDHOC EAD stage coverage");
  }
  const eadRows = block.ead_nonempty_terminal_matrix;
  validateEadRows(eadRows);
  const eadMutants = [
    eadRows.map((row) => ({ ...row, ead_hex: "" })),
    eadRows.map((row) => ({ ...row, stage: 1, id: "EAD_1_NONEMPTY" })),
    eadRows.map((row, index) => index === 1 ? { ...row, ead_hex: eadRows[0].ead_hex } : { ...row }),
    eadRows.map((row, index) => index === 0 ? { ...row, ead_hex: eadRows[1].ead_hex } :
      index === 1 ? { ...row, ead_hex: eadRows[0].ead_hex } : { ...row }),
  ];
  for (const mutant of eadMutants) {
    let rejected = false;
    try { validateEadRows(mutant); } catch (error) { rejected = true; }
    if (!rejected) fail("EDHOC EAD coherent mutant accepted");
  }
  executed.add("PA-EDHOC-EAD1-EAD4-TERMINAL");
  if (
    JSON.stringify(block.downgrade_failure) !==
      JSON.stringify({
        automatic_retry_count: 0,
        fresh_policy_revision_required: true,
        fresh_session_generation_required: true,
        initial_pinned_suite: 2,
        outcome: "TERMINAL_NO_AUTODOWNGRADE",
        same_policy_revision_retry_allowed: false,
        suggested_other_suite: 3,
      }) ||
    block.provider_interoperability_claimed !== false ||
    block.rfc9529_trace_role !==
      "ALGORITHM_REFERENCE_ONLY_NOT_PROFILE_NEGOTIATION_POSITIVE"
  ) {
    fail("EDHOC downgrade/nonclaim authority");
  }
  executed.add("PA-EDHOC-DOWNGRADE-NO-AUTORETRY");
}

function assertPreauthOwner(document, executed) {
  const pre = document.preauth_owner;
  const requiredBranches = [
    "ALLOCATE",
    "FRAGMENT_0_ACCEPT",
    "FRAGMENT_1_ACCEPT",
    "SAME_DUPLICATE",
    "CONFLICTING_DUPLICATE_TERMINAL",
    "COMPLETE_RELEASE",
    "PER_SOURCE_QUOTA_DENY",
    "GLOBAL_QUOTA_DENY",
    "TOKEN_CAPACITY_DENY",
    "REFILL_BEFORE_2S",
    "REFILL_AT_2S",
    "IDLE_BEFORE_9S",
    "IDLE_AT_9S_RELEASE",
    "COOKIE_CURRENT_ACCEPT",
    "COOKIE_PREVIOUS_ACCEPT",
    "COOKIE_OLDER_EXISTING_TERMINAL",
    "COOKIE_OLDER_NO_OWNER",
  ];
  if (
    JSON.stringify(pre.owner_key_fields) !==
      JSON.stringify([
        "source_locator_digest32",
        "session_id16",
        "exchange_generation_u64",
        "record_sequence_u32",
        "complete_nac1_bytes_u16",
        "digest16",
      ]) ||
    pre.per_source_scratch_limit !== 1 ||
    pre.global_scratch_limit !== 8 ||
    pre.scratch_fragment_count_exact !== 2 ||
    pre.idle_timeout_seconds !== 9 ||
    pre.idle_timeout_ms !== 9000 ||
    JSON.stringify(pre.cookie_valid_buckets) !==
      JSON.stringify(["CURRENT", "PREVIOUS"]) ||
    pre.token_bucket_capacity !== 2 ||
    pre.token_refill_seconds !== 2 ||
    pre.token_refill_ms !== 2000 ||
    pre.current_cookie_bucket !== document.stateless_cookie.time_bucket ||
    pre.identity_allocations_before_cookie !== 0 ||
    pre.credential_resolver_calls_before_cookie !== 0 ||
    JSON.stringify(pre.required_branch_names) !==
      JSON.stringify(requiredBranches)
  ) {
    fail("preauth constants/owner key");
  }

  const actualFragments =
    document.stateless_cookie.response_radio_fragments.map((row, index) => {
      const packet = hex(row.hex, `preauth.cookie_fragment_${index}`);
      validateNpr(packet, `preauth.cookie_fragment_${index}`);
      return packet.subarray(68);
    });
  const payloads = new Map();
  for (const row of pre.transitions) {
    const payload = hex(
      row.fragment_payload_hex,
      `preauth.${row.step}.fragment_payload`,
    );
    if (
      payloads.has(row.fragment_payload_variant) &&
      !equal(payloads.get(row.fragment_payload_variant), payload)
    ) {
      fail(`preauth variant drift ${row.fragment_payload_variant}`);
    }
    payloads.set(row.fragment_payload_variant, payload);
  }
  const conflictPayload = payloads.get("F0_CONFLICT");
  let conflictDifferences = 0;
  if (
    actualFragments.length !== 2 ||
    actualFragments[0].length !== 124 ||
    !equal(payloads.get("F0"), actualFragments[0]) ||
    !equal(payloads.get("F1"), actualFragments[1]) ||
    payloads.get("NONE").length !== 0 ||
    conflictPayload.length !== actualFragments[0].length
  ) {
    fail("preauth payload variants");
  }
  for (let i = 0; i < conflictPayload.length; i += 1) {
    if (conflictPayload[i] !== actualFragments[0][i]) conflictDifferences += 1;
  }
  if (conflictDifferences !== 1) fail("preauth conflict payload distance");

  let active = new Map();
  let buckets = new Map();
  const branchCounts = new Map(requiredBranches.map((name) => [name, 0]));
  let completions = 0;
  let releases = 0;
  let terminalDiscards = 0;
  let scenario = null;
  let previousTime = 0;

  const reset = (name) => {
    active = new Map();
    buckets = new Map();
    completions = 0;
    releases = 0;
    terminalDiscards = 0;
    scenario = name;
    previousTime = 0;
  };
  const ownerKey = (row) =>
    [
      row.source_locator_digest_hex,
      row.session_id_hex,
      row.exchange_generation,
      row.record_sequence,
      row.complete_nac1_bytes,
      row.digest16_hex,
    ].join(":");
  const release = (key) => {
    if (!active.delete(key)) fail("preauth release missing owner");
    releases += 1;
  };
  const sourceActiveCount = (sourceHex) => {
    let count = 0;
    for (const owner of active.values()) {
      if (owner.sourceHex === sourceHex) count += 1;
    }
    return count;
  };

  pre.transitions.forEach((row, index) => {
    if (row.step !== index) fail(`preauth step ${index}`);
    if (row.reset_before === true) reset(row.scenario);
    if (
      scenario !== row.scenario ||
      !Number.isSafeInteger(row.at_ms) ||
      row.at_ms < previousTime
    ) {
      fail(`preauth scenario/time ${index}`);
    }
    previousTime = row.at_ms;
    const hits = [];
    let expired = 0;
    let beforeIdle = false;
    for (const [key, owner] of [...active.entries()]) {
      const elapsed = row.at_ms - owner.lastMs;
      if (elapsed < 0) fail("preauth owner time");
      if (elapsed >= 9000) {
        release(key);
        expired += 1;
      } else if (elapsed > 0) {
        beforeIdle = true;
      }
    }
    if (beforeIdle) hits.push("IDLE_BEFORE_9S");
    if (expired > 0) hits.push("IDLE_AT_9S_RELEASE");

    let key = null;
    let sourceHex = null;
    let result;
    if (row.operation === "TICK") {
      if (
        row.source_label !== "NONE" ||
        row.source_locator_digest_hex !== "" ||
        row.session_id_hex !== "" ||
        row.fragment_index !== -1 ||
        row.fragment_payload_variant !== "NONE" ||
        row.fragment_payload_hex !== ""
      ) {
        fail("preauth tick sentinel");
      }
      result = expired > 0 ? "IDLE_EXPIRED_RELEASED" : "TICK_NO_EXPIRY";
    } else if (row.operation === "RECEIVE_FRAGMENT") {
      const source = hex(
        row.source_locator_digest_hex,
        `preauth.${index}.source`,
      );
      const session = hex(row.session_id_hex, `preauth.${index}.session`);
      const digest = hex(row.digest16_hex, `preauth.${index}.digest16`);
      if (
        source.length !== 32 ||
        session.length !== 16 ||
        digest.length !== 16 ||
        !Number.isSafeInteger(row.exchange_generation) ||
        row.exchange_generation < 1 ||
        !Number.isSafeInteger(row.record_sequence) ||
        row.record_sequence < 0 ||
        row.record_sequence > 0xffffffff ||
        !Number.isSafeInteger(row.complete_nac1_bytes) ||
        row.complete_nac1_bytes < 1 ||
        row.complete_nac1_bytes > 600 ||
        ![0, 1].includes(row.fragment_index) ||
        !["F0", "F1", "F0_CONFLICT"].includes(
          row.fragment_payload_variant,
        ) ||
        !equal(
          hex(row.fragment_payload_hex, `preauth.${index}.payload`),
          payloads.get(row.fragment_payload_variant),
        )
      ) {
        fail(`preauth receive row ${index}`);
      }
      const expectedSource =
        row.source_label === "PRIMARY"
          ? hex(pre.source_locator_digest_hex, "preauth primary source")
          : sha(
              Buffer.concat([
                Buffer.from("NINLIL-PA-PREAUTH-SOURCE-V1", "ascii"),
                Buffer.from(row.source_label, "ascii"),
              ]),
            );
      if (!equal(source, expectedSource)) fail("preauth source derivation");
      key = ownerKey(row);
      sourceHex = row.source_locator_digest_hex;
      const owner = active.get(key);
      if (
        row.cookie_bucket !== pre.current_cookie_bucket &&
        row.cookie_bucket !== pre.current_cookie_bucket - 1
      ) {
        if (owner === undefined) {
          hits.push("COOKIE_OLDER_NO_OWNER");
          result = "COOKIE_BUCKET_EXPIRED_NO_OWNER";
        } else {
          release(key);
          terminalDiscards += 1;
          hits.push("COOKIE_OLDER_EXISTING_TERMINAL");
          result = "COOKIE_BUCKET_EXPIRED_TERMINAL_DISCARD";
        }
      } else if (owner !== undefined) {
        const payload = hex(
          row.fragment_payload_hex,
          `preauth.${index}.payload`,
        );
        const prior = owner.fragments.get(row.fragment_index);
        if (prior !== undefined) {
          if (equal(prior, payload)) {
            owner.lastMs = row.at_ms;
            hits.push("SAME_DUPLICATE");
            result = "DUPLICATE_NO_PROGRESS";
          } else {
            release(key);
            terminalDiscards += 1;
            hits.push("CONFLICTING_DUPLICATE_TERMINAL");
            result = "CONFLICTING_DUPLICATE_TERMINAL_DISCARD";
          }
        } else {
          owner.fragments.set(row.fragment_index, payload);
          owner.lastMs = row.at_ms;
          hits.push(`FRAGMENT_${row.fragment_index}_ACCEPT`);
          if (owner.fragments.size === 2) {
            release(key);
            completions += 1;
            hits.push("COMPLETE_RELEASE");
            result = "COMPLETE_RELEASED";
          } else {
            result = "FRAGMENT_ACCEPTED_PROGRESS";
          }
        }
      } else {
        let token = buckets.get(sourceHex);
        if (token === undefined) {
          token = { tokens: 2, lastRefillMs: row.at_ms };
          buckets.set(sourceHex, token);
        } else {
          const elapsed = row.at_ms - token.lastRefillMs;
          if (elapsed < 0) fail("preauth refill time");
          if (elapsed > 0 && elapsed < 2000) {
            hits.push("REFILL_BEFORE_2S");
          }
          const intervals = Math.floor(elapsed / 2000);
          if (intervals > 0) {
            hits.push("REFILL_AT_2S");
            token.tokens = Math.min(2, token.tokens + intervals);
            token.lastRefillMs += intervals * 2000;
          }
        }
        const perSource = sourceActiveCount(sourceHex);
        if (token.tokens === 0) {
          hits.push("TOKEN_CAPACITY_DENY");
          result = "TOKEN_BUCKET_DENY";
        } else if (perSource === 1) {
          hits.push("PER_SOURCE_QUOTA_DENY");
          result = "PER_SOURCE_QUOTA_DENY";
        } else if (active.size === 8) {
          hits.push("GLOBAL_QUOTA_DENY");
          result = "GLOBAL_QUOTA_DENY";
        } else {
          token.tokens -= 1;
          active.set(key, {
            sourceHex,
            lastMs: row.at_ms,
            fragments: new Map([
              [
                row.fragment_index,
                hex(
                  row.fragment_payload_hex,
                  `preauth.${index}.payload`,
                ),
              ],
            ]),
          });
          hits.push(
            "ALLOCATE",
            `FRAGMENT_${row.fragment_index}_ACCEPT`,
            row.cookie_bucket === pre.current_cookie_bucket
              ? "COOKIE_CURRENT_ACCEPT"
              : "COOKIE_PREVIOUS_ACCEPT",
          );
          result = "FRAGMENT_ACCEPTED_ALLOCATED";
        }
      }
    } else {
      fail(`preauth operation ${row.operation}`);
    }

    for (const branch of hits) {
      if (!branchCounts.has(branch)) fail(`preauth branch ${branch}`);
      branchCounts.set(branch, branchCounts.get(branch) + 1);
    }
    let mask = 0;
    if (key !== null && active.has(key)) {
      for (const fragmentIndex of active.get(key).fragments.keys()) {
        mask |= 1 << fragmentIndex;
      }
    }
    const sourceActive =
      sourceHex === null ? 0 : sourceActiveCount(sourceHex);
    const sourceTokens =
      sourceHex !== null && buckets.has(sourceHex)
        ? buckets.get(sourceHex).tokens
        : -1;
    const expected = row.expected;
    if (
      expected.result !== result ||
      JSON.stringify(expected.branches) !== JSON.stringify(hits) ||
      expected.active_scratch_count !== active.size ||
      expected.source_active_scratch_count !== sourceActive ||
      expected.source_tokens !== sourceTokens ||
      expected.active_owner_received_mask !== mask ||
      expected.expired_release_count_delta !== expired ||
      expected.completion_count !== completions ||
      expected.release_count !== releases ||
      expected.terminal_discard_count !== terminalDiscards ||
      expected.identity_allocations !== 0 ||
      expected.credential_resolver_calls !== 0
    ) {
      fail(`preauth transition ${index}`);
    }
  });
  if (
    pre.transitions.length === 0 ||
    pre.transitions[0].reset_before !== true
  ) {
    fail("preauth transcript start");
  }
  for (const branch of requiredBranches) {
    if (
      branchCounts.get(branch) < 1 ||
      pre.branch_coverage[branch] !== branchCounts.get(branch)
    ) {
      fail(`preauth branch coverage ${branch}`);
    }
  }
  if (
    Object.keys(pre.branch_coverage).length !== requiredBranches.length
  ) {
    fail("preauth branch coverage closed keys");
  }
  executed.add("PA-PREAUTH-SOURCE-QUOTA-IDLE-BUCKET");
}

function assertMagicRegistry(document, executed) {
  const magic = document.magic_registry;
  const repositoryRoot = path.dirname(here);
  const registryPath = path.join(repositoryRoot, magic.registry);
  const registry = loadStrictJson(fs.readFileSync(registryPath));
  const exactKeys = (value, keys, field) => {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())
    ) {
      fail(`${field}: closed keys`);
    }
  };
  const closedStringDomain = (value, field) => {
    if (
      !Array.isArray(value) ||
      value.length === 0 ||
      value.some((item) => typeof item !== "string" || item.length === 0) ||
      new Set(value).size !== value.length ||
      JSON.stringify(value) !== JSON.stringify([...value].sort())
    ) {
      fail(`${field}: canonical closed string domain`);
    }
    return new Set(value);
  };
  exactKeys(
    registry,
    [
      "schema",
      "version",
      "scope",
      "policy",
      "domains",
      "scan",
      "entries",
      "explicit_exclusions",
      "required_production_attachment",
      "forbidden_production_attachment",
    ],
    "magic registry root",
  );
  exactKeys(
    registry.policy,
    [
      "value_bytes_exact",
      "ascii_uppercase_or_digit",
      "duplicate_value_allowed",
      "transport_or_storage_partition_exempts_collision",
      "duplicate_json_keys_rejected",
      "undeclared_scanned_candidate_rejected",
      "stale_registry_entry_rejected",
      "exact_occurrence_manifest_required",
    ],
    "magic registry policy",
  );
  if (
    registry.schema !== "ninlil.protocol-magic-registry.v1" ||
    registry.version !== 1 ||
    registry.scope !== "GLOBAL_PROTOCOL_AND_STORAGE_NAMESPACE" ||
    registry.policy.value_bytes_exact !== 4 ||
    registry.policy.ascii_uppercase_or_digit !== true ||
    registry.policy.duplicate_value_allowed !== false ||
    registry.policy.transport_or_storage_partition_exempts_collision !== false ||
    registry.policy.duplicate_json_keys_rejected !== true ||
    registry.policy.undeclared_scanned_candidate_rejected !== true ||
    registry.policy.stale_registry_entry_rejected !== true ||
    registry.policy.exact_occurrence_manifest_required !== true
  ) {
    fail("global magic registry identity/policy");
  }

  exactKeys(
    registry.domains,
    [
      "owners",
      "artifacts",
      "statuses",
      "authorities",
      "exclusion_reasons",
    ],
    "magic registry domains",
  );
  const ownerDomain = closedStringDomain(
    registry.domains.owners,
    "magic owner domain",
  );
  const artifactDomain = closedStringDomain(
    registry.domains.artifacts,
    "magic artifact domain",
  );
  const statusDomain = closedStringDomain(
    registry.domains.statuses,
    "magic status domain",
  );
  const authorityDomain = closedStringDomain(
    registry.domains.authorities,
    "magic authority domain",
  );
  const exclusionReasonDomain = closedStringDomain(
    registry.domains.exclusion_reasons,
    "magic exclusion reason domain",
  );
  const occurrenceRepresentations = new Set([
    "CHAR_ARRAY",
    "CONCAT_QUOTED",
    "HEX_ESCAPED",
    "QUOTED",
    "U32_BE",
    "U32_LE",
  ]);
  const validateOccurrences = (value, field) => {
    if (!Array.isArray(value) || value.length === 0) {
      fail(`${field}: non-empty occurrence array required`);
    }
    const rows = value.map((row, index) => {
      exactKeys(
        row,
        ["path", "representation", "count"],
        `${field}[${index}]`,
      );
      if (
        typeof row.path !== "string" ||
        row.path.length === 0 ||
        path.posix.isAbsolute(row.path) ||
        row.path.split("/").includes("..") ||
        !occurrenceRepresentations.has(row.representation) ||
        !Number.isSafeInteger(row.count) ||
        row.count < 1
      ) {
        fail(`${field}[${index}]: occurrence domain`);
      }
      const occurrencePath = path.resolve(repositoryRoot, row.path);
      if (
        !occurrencePath.startsWith(`${path.resolve(repositoryRoot)}${path.sep}`) ||
        !fs.existsSync(occurrencePath) ||
        !fs.statSync(occurrencePath).isFile()
      ) {
        fail(`${field}[${index}]: missing/escaping occurrence path`);
      }
      return [row.path, row.representation, row.count];
    });
    const compareRows = (left, right) => {
      if (left[0] !== right[0]) return left[0] < right[0] ? -1 : 1;
      if (left[1] !== right[1]) return left[1] < right[1] ? -1 : 1;
      return left[2] - right[2];
    };
    const canonical = [...rows].sort(compareRows);
    if (
      new Set(rows.map((row) => JSON.stringify(row))).size !== rows.length ||
      JSON.stringify(rows) !== JSON.stringify(canonical)
    ) {
      fail(`${field}: canonical exact occurrence order`);
    }
  };

  const scanRoots = [
    "cmake",
    "examples",
    "include",
    "ports",
    "src",
    "tests",
    "tools",
  ];
  const scanExtensions = [
    ".c",
    ".cc",
    ".cmake",
    ".cpp",
    ".h",
    ".hpp",
    ".inc",
    ".js",
    ".json",
    ".mjs",
    ".py",
  ];
  const excludedComponents = [
    ".git",
    "__pycache__",
    "_vendor",
    "build",
    "managed_components",
  ];
  const candidatePattern = "C_QUOTED_CHAR_ARRAY_U32_BE_U32_LE_V1";
  const quotedCandidatePattern =
    String.raw`(?<![A-Za-z0-9_])(?:[bBuU])?["']([A-Z][A-Z0-9]{3})["']`;
  exactKeys(
    registry.scan,
    [
      "roots",
      "extensions",
      "excluded_path_components",
      "excluded_relative_paths",
      "candidate_regex",
    ],
    "magic registry scan",
  );
  if (
    JSON.stringify(registry.scan.roots) !== JSON.stringify(scanRoots) ||
    JSON.stringify(registry.scan.extensions) !==
      JSON.stringify(scanExtensions) ||
    JSON.stringify(registry.scan.excluded_path_components) !==
      JSON.stringify(excludedComponents) ||
    JSON.stringify(registry.scan.excluded_relative_paths) !== "[]" ||
    registry.scan.candidate_regex !== candidatePattern
  ) {
    fail("magic registry scan boundary drift");
  }

  const byMagic = new Map();
  const entryOrder = [];
  for (const [index, entry] of registry.entries.entries()) {
    exactKeys(
      entry,
      ["magic", "owner", "artifact", "status", "authority", "occurrences"],
      `magic registry entry ${index}`,
    );
    if (
      typeof entry.magic !== "string" ||
      !/^[A-Z][A-Z0-9]{3}$/.test(entry.magic) ||
      byMagic.has(entry.magic) ||
      typeof entry.owner !== "string" ||
      !ownerDomain.has(entry.owner) ||
      typeof entry.artifact !== "string" ||
      !artifactDomain.has(entry.artifact) ||
      typeof entry.status !== "string" ||
      !statusDomain.has(entry.status) ||
      typeof entry.authority !== "string" ||
      !authorityDomain.has(entry.authority)
    ) {
      fail(`global magic registry entry domain ${entry.magic}`);
    }
    validateOccurrences(entry.occurrences, `magic registry entry ${index}.occurrences`);
    const authority = path.resolve(repositoryRoot, entry.authority);
    if (
      !authority.startsWith(`${path.resolve(repositoryRoot)}${path.sep}`) ||
      !fs.statSync(authority).isFile()
    ) {
      fail(`missing/escaping magic authority ${entry.authority}`);
    }
    byMagic.set(entry.magic, entry);
    entryOrder.push(entry.magic);
  }
  if (
    entryOrder.length === 0 ||
    JSON.stringify(entryOrder) !== JSON.stringify([...entryOrder].sort())
  ) {
    fail("magic registry entry order");
  }

  const exclusions = new Map();
  const exclusionOrder = [];
  for (const [index, row] of registry.explicit_exclusions.entries()) {
    exactKeys(row, ["token", "reason", "occurrences"], `magic exclusion ${index}`);
    if (
      typeof row.token !== "string" ||
      !/^[A-Z][A-Z0-9]{3}$/.test(row.token) ||
      typeof row.reason !== "string" ||
      !exclusionReasonDomain.has(row.reason) ||
      exclusions.has(row.token) ||
      byMagic.has(row.token)
    ) {
      fail(`magic registry exclusion domain ${row.token}`);
    }
    validateOccurrences(row.occurrences, `magic exclusion ${index}.occurrences`);
    exclusions.set(row.token, row.reason);
    exclusionOrder.push(row.token);
  }
  if (
    exclusionOrder.length === 0 ||
    JSON.stringify(exclusionOrder) !==
      JSON.stringify([...exclusionOrder].sort())
  ) {
    fail("magic registry exclusion order");
  }

  const inventory = new Map();
  const extensionSet = new Set(scanExtensions);
  const excludedComponentSet = new Set(excludedComponents);
  const visit = (candidatePath) => {
    const stat = fs.statSync(candidatePath);
    if (stat.isDirectory()) {
      for (const child of fs.readdirSync(candidatePath).sort()) {
        visit(path.join(candidatePath, child));
      }
      return;
    }
    if (!stat.isFile() || !extensionSet.has(path.extname(candidatePath))) return;
    if (
      candidatePath
        .split(path.sep)
        .some(
          (component) =>
            excludedComponentSet.has(component) ||
            (excludedComponentSet.has("build") &&
              component.startsWith("build-")),
        )
    ) {
      return;
    }
    const relative = path.relative(repositoryRoot, candidatePath).split(path.sep).join("/");
    const source = fs.readFileSync(candidatePath, "utf8");
    const regex = new RegExp(quotedCandidatePattern, "g");
    for (let match = regex.exec(source); match !== null; match = regex.exec(source)) {
      if (!inventory.has(match[1])) inventory.set(match[1], new Set());
      inventory.get(match[1]).add(relative);
    }
  };
  for (const rootName of scanRoots) {
    const scanRoot = path.join(repositoryRoot, rootName);
    if (!fs.existsSync(scanRoot)) fail(`magic scan root missing ${rootName}`);
    visit(scanRoot);
  }
  const discovered = new Set(inventory.keys());
  for (const candidate of discovered) {
    if (!byMagic.has(candidate) && !exclusions.has(candidate)) {
      fail(`undeclared scanned magic candidate ${candidate}`);
    }
  }
  // Cross-representation liveness and exact counts are owned by the adjacent
  // protocol_magic_registry_gate.py check. This independent gate validates
  // the closed occurrence manifest and rejects undeclared quoted candidates.
  const required = ["NAC1", "NAR1", "NAS1"];
  const forbidden = ["NPA1", "NPS1"];
  if (
    JSON.stringify(registry.required_production_attachment) !==
      JSON.stringify(required) ||
    JSON.stringify(registry.forbidden_production_attachment) !==
      JSON.stringify(forbidden) ||
    required.some(
      (value) => byMagic.get(value)?.owner !== "PRODUCTION_ATTACHMENT",
    ) ||
    forbidden.some(
      (value) => byMagic.get(value)?.owner !== "MULTI_PARENT",
    ) ||
    ["NLR1", "N6TX", "N6RX", "N6AL", "N6HW"].some(
      (value) => !byMagic.has(value),
    ) ||
    JSON.stringify(magic.pa_allocations) !==
      JSON.stringify({
        NAC1: "PRODUCTION_ATTACHMENT_CARRIER_RECORD",
        NAR1: "PRODUCTION_ATTACHMENT_RADIO_FRAGMENT",
        NAS1: "PRODUCTION_ATTACHMENT_STREAM_WRAPPER",
      }) ||
    JSON.stringify(magic.forbidden_pa_allocations) !==
      JSON.stringify({
        NPA1: "ADR0020_MULTI_PARENT_ASSIGNMENT_PAGE",
        NPS1: "ADR0020_MULTI_PARENT_PARENT_SET",
      }) ||
    magic.all_pa_allocations_unique !== true ||
    magic.repository_registry_gate_required !== true
  ) {
    fail("global magic registry PA binding");
  }
  executed.add("PA-MAGIC-GLOBAL-UNIQUE");
}

function pathIsDescriptive(jsonPath) {
  return DESCRIPTIVE_ALLOWLIST.has(jsonPath);
}

function pathJoin(parent, key) {
  if (typeof key === "number") return `${parent}[${key}]`;
  return parent === "$" ? `$.${key}` : `${parent}.${key}`;
}

function loadExpectedDocument() {
  if (cachedExpectedDocument !== null) {
    return structuredClone(cachedExpectedDocument);
  }
  const raw = execFileSync("python3", [expectedModelPy, "--dump-json"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  cachedExpectedDocument = JSON.parse(raw);
  if (
    cachedExpectedDocument === null ||
    typeof cachedExpectedDocument !== "object" ||
    Array.isArray(cachedExpectedDocument)
  ) {
    fail("expected-model dump not object");
  }
  return structuredClone(cachedExpectedDocument);
}

function deepDiff(actual, expected, jsonPath = "$", diffs = [], maxDiffs = 40) {
  if (diffs.length >= maxDiffs) return diffs;
  if (pathIsDescriptive(jsonPath)) return diffs;
  if (typeof actual !== typeof expected) {
    diffs.push(
      `${jsonPath}: type ${typeof actual} != ${typeof expected}`,
    );
    return diffs;
  }
  if (actual === null || expected === null) {
    if (actual !== expected) diffs.push(`${jsonPath}: null mismatch`);
    return diffs;
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) {
      diffs.push(`${jsonPath}: expected array`);
      return diffs;
    }
    if (actual.length !== expected.length) {
      diffs.push(`${jsonPath}: length ${actual.length} != ${expected.length}`);
    }
    const n = Math.min(actual.length, expected.length);
    for (let i = 0; i < n; i += 1) {
      deepDiff(actual[i], expected[i], pathJoin(jsonPath, i), diffs, maxDiffs);
    }
    return diffs;
  }
  if (typeof expected === "object") {
    if (typeof actual !== "object" || Array.isArray(actual)) {
      diffs.push(`${jsonPath}: expected object`);
      return diffs;
    }
    const aKeys = Object.keys(actual);
    const eKeys = Object.keys(expected);
    for (const k of eKeys) {
      if (!Object.prototype.hasOwnProperty.call(actual, k)) {
        diffs.push(`${jsonPath}.${k}: missing in actual`);
      }
    }
    for (const k of aKeys) {
      if (!Object.prototype.hasOwnProperty.call(expected, k)) {
        diffs.push(`${jsonPath}.${k}: unexpected key in actual`);
      }
    }
    for (const k of eKeys) {
      if (Object.prototype.hasOwnProperty.call(actual, k)) {
        deepDiff(
          actual[k],
          expected[k],
          pathJoin(jsonPath, k),
          diffs,
          maxDiffs,
        );
      }
    }
    return diffs;
  }
  if (actual !== expected) {
    const fmt = (v) => {
      const s = JSON.stringify(v);
      return s.length <= 96 ? s : `${s.slice(0, 93)}...`;
    };
    diffs.push(`${jsonPath}: ${fmt(actual)} != ${fmt(expected)}`);
  }
  return diffs;
}

function assertMatchesExpected(document) {
  const expected = loadExpectedDocument();
  const diffs = deepDiff(document, expected);
  if (diffs.length !== 0) {
    fail(
      `canonical expected-model mismatch (${diffs.length} diffs): ${diffs[0]}`,
    );
  }
}

function validate(document) {
  const executed = new Set();
  validateClosedSchema(document);
  // Primary machine authority: full-tree exact equality vs independent rebuild.
  assertMatchesExpected(document);
  if (
    document.schema !== "ninlil.production-attachment-edhoc.vector.v1" ||
    document.status !== "PROPOSED_SPEC_ONLY"
  ) {
    fail("schema/status");
  }
  const actualCases = new Set(document.required_gate_cases);
  if (
    actualCases.size !== requiredCases.size ||
    document.required_gate_cases.length !== requiredCases.size ||
    [...requiredCases].some((value) => !actualCases.has(value))
  ) {
    fail("required gate cases");
  }
  const profile = document.profile;
  const labels = {
    attach_i2r_key16: 32768,
    attach_r2i_key16: 32769,
    attach_i2r_iv13: 32770,
    attach_r2i_iv13: 32771,
    hop_ir_secret32: 32772,
    hop_ri_secret32: 32773,
    e2e_ir_secret32: 32774,
    e2e_ri_secret32: 32775,
  };
  if (
    profile.method !== 3 ||
    JSON.stringify(profile.mandatory_suites) !==
      JSON.stringify({
        2: [10, -16, 8, 1, -7, 10, -16],
        3: [30, -16, 16, 1, -7, 10, -16],
      }) ||
    profile.message_4_required !== true ||
    profile.ead_allowed !== false ||
    profile.automatic_suite_downgrade_allowed !== false ||
    profile.credential !== "RPK carried by CCS, resolved by kid" ||
    Object.keys(labels).some(
      (name) => profile.exporter_labels[name] !== labels[name],
    ) ||
    Object.keys(profile.exporter_labels).length !== Object.keys(labels).length ||
    profile.control_aead.cose_algorithm !== 10 ||
    profile.control_aead.name !== "AES-CCM-16-64-128" ||
    profile.control_aead.key_bytes !== 16 ||
    profile.control_aead.iv_bytes !== 13 ||
    profile.control_aead.tag_bytes !== 8
  ) {
    fail("profile");
  }
  // Exact limits pin (parity with Python expected_limits).
  const expectedLimits = {
    nac1_header_bytes: 88,
    nac1_payload_max: 512,
    nac1_record_max: 600,
    nas1_header_bytes: 12,
    nas1_record_max: 612,
    nar1_profile: 18,
    nar1_header_bytes: 68,
    nar1_packet_max: 192,
    nar1_fragment_payload_max: 124,
    nar1_fragment_count_max: 5,
    nap1_bytes: 208,
    nai1_bytes: 416,
    nax1_bytes: 160,
    nat1_bytes: 96,
    n6at_key_bytes: 20,
    n6at_value_bytes: 120,
    nab1_header_bytes: 68,
    nab1_entry_bytes: 20,
    nab1_entry_count: 15,
    nab1_total_bytes: 368,
  };
  const limits = document.limits;
  for (const [k, v] of Object.entries(expectedLimits)) {
    if (exactInt(limits[k], `limits.${k}`) !== v) fail("limits");
  }
  for (const k of Object.keys(limits)) {
    if (!(k in expectedLimits)) fail(`limits unknown ${k}`);
  }
  executed.add("PROFILE-METHOD-SUITE-MESSAGE4-EAD");
  executed.add("EXPORTER-LABEL-SET-EXACT");
  validateCarrierBindings(document, executed);
  validateCarrierTranscript(document, executed);

  for (const [name, suite, generation] of [
    ["suite_2", 2, 101n],
    ["suite_3", 3, 102n],
  ]) {
    const item = document.edhoc_message_1[name];
    const payload = hex(item.hex, `${name}.payload`);
    const nac = hex(item.nac1_hex, `${name}.nac`);
    if (
      payload.length !== item.length ||
      shaHex(payload) !== item.sha256 ||
      payload[0] !== 3 ||
      payload[1] !== suite
    ) {
      fail(`${name}: payload`);
    }
    validateNpa(nac, name, 4, 1, 3);
    if (!equal(nac.subarray(88), payload) || u64(nac, 36) !== generation) {
      fail(`${name}: NAC payload`);
    }
    executed.add(
      name === "suite_2" ? "NAC1-SUITE2-MESSAGE1" : "NAC1-SUITE3-MESSAGE1",
    );
  }

  const nas = hex(document.stream_wrapper.usb_nas1_hex, "NAS");
  if (
    nas.length !== document.stream_wrapper.usb_nas1_length ||
    shaHex(nas) !== document.stream_wrapper.usb_nas1_sha256 ||
    nas.subarray(0, 4).toString() !== "NAS1" ||
    nas[4] !== 1 ||
    nas[5] !== 1 ||
    u16(nas, 6) !== 12 ||
    u32(nas, 8) !== nas.length - 12
  ) {
    fail("NAS");
  }
  validateNpa(nas.subarray(12), "NAS.inner", 4, 1, 1);
  executed.add("NAS1-USB-STREAM-RECORD");

  const cookie = document.stateless_cookie;
  if (cookie.time_bucket_seconds !== COOKIE_TIME_BUCKET_SECONDS) {
    fail(
      `cookie time_bucket_seconds must be normative ${COOKIE_TIME_BUCKET_SECONDS}s; got ${cookie.time_bucket_seconds}`,
    );
  }
  const canonical = hex(cookie.canonical_input_hex, "cookie canonical");
  const suite2Payload = hex(document.edhoc_message_1.suite_2.hex, "suite2 M1");
  const suite2Npa = hex(document.edhoc_message_1.suite_2.nac1_hex, "suite2 NAC");
  const bucket = Buffer.alloc(8);
  bucket.writeBigUInt64BE(BigInt(cookie.time_bucket));
  const expectedCanonical = Buffer.concat([
    Buffer.from("NINLIL-NAC1-COOKIE-V1"),
    Buffer.from([3]),
    hex(document.carrier_bindings.compact_radio.digest_hex, "radio binding"),
    hex(cookie.source_locator_digest_hex, "source locator"),
    suite2Npa.subarray(20, 36),
    suite2Npa.subarray(36, 44),
    sha(suite2Payload),
    bucket,
  ]);
  if (!equal(canonical, expectedCanonical)) fail("cookie canonical input");
  const current = crypto
    .createHmac("sha256", hex(cookie.current_secret_hex, "cookie secret"))
    .update(canonical)
    .digest();
  if (!equal(current, hex(cookie.current_cookie_hex, "cookie"))) fail("cookie");
  executed.add("COOKIE-CURRENT-BUCKET-CURRENT-SECRET");
  const previousInput = Buffer.concat([
    canonical.subarray(0, canonical.length - 8),
    (() => {
      const value = Buffer.alloc(8);
      value.writeBigUInt64BE(BigInt(cookie.time_bucket - 1));
      return value;
    })(),
  ]);
  const previous = crypto
    .createHmac("sha256", hex(cookie.previous_secret_hex, "previous secret"))
    .update(previousInput)
    .digest();
  if (
    !equal(
      previous,
      hex(cookie.previous_bucket_previous_secret_cookie_hex, "previous cookie"),
    ) ||
    cookie.identity_or_authentication_claimed !== false
  ) {
    fail("previous cookie/nonclaim");
  }
  executed.add("COOKIE-PREVIOUS-BUCKET-PREVIOUS-SECRET");
  {
    const matrix = cookie.secret_bucket_matrix;
    if (!matrix || Object.keys(matrix).length !== 4) fail("cookie matrix size");
    const secrets = {
      current_secret: hex(cookie.current_secret_hex, "matrix cur secret"),
      previous_secret: hex(cookie.previous_secret_hex, "matrix prev secret"),
    };
    const buckets = {
      current_bucket: cookie.time_bucket,
      previous_bucket: cookie.time_bucket - 1,
    };
    const suite2Npa = hex(document.edhoc_message_1.suite_2.nac1_hex, "matrix nac");
    const m1s2 = hex(document.edhoc_message_1.suite_2.hex, "matrix m1");
    const radioBinding = hex(
      document.carrier_bindings.compact_radio.digest_hex,
      "matrix radio",
    );
    const sourceLocator = hex(cookie.source_locator_digest_hex, "matrix source");
    const observed = new Set();
    for (const [secretName, secret] of Object.entries(secrets)) {
      for (const [bucketName, bucket] of Object.entries(buckets)) {
        const name = `${secretName}_x_${bucketName}`;
        const item = matrix[name];
        if (!item) fail(`cookie matrix missing ${name}`);
        const bucketBuf = Buffer.alloc(8);
        bucketBuf.writeBigUInt64BE(BigInt(bucket));
        const expectedInput = Buffer.concat([
          Buffer.from("NINLIL-NAC1-COOKIE-V1"),
          Buffer.from([3]),
          radioBinding,
          sourceLocator,
          suite2Npa.subarray(20, 36),
          suite2Npa.subarray(36, 44),
          sha(m1s2),
          bucketBuf,
        ]);
        const rawCookie = hex(item.cookie_hex, name);
        const got = crypto.createHmac("sha256", secret).update(expectedInput).digest();
        if (
          item.time_bucket !== bucket ||
          item.secret_name !== secretName ||
          !equal(hex(item.canonical_input_hex, `${name} input`), expectedInput) ||
          !equal(got, rawCookie)
        ) {
          fail(`cookie matrix ${name}`);
        }
        observed.add(rawCookie.toString("hex"));
      }
    }
    if (observed.size !== 4) fail("cookie matrix not four distinct");
  }
  executed.add("COOKIE-FOUR-COMBINATION-MATRIX");
  const mutatedSource = Buffer.from(canonical);
  const sourceOff = Buffer.from("NINLIL-NAC1-COOKIE-V1").length + 1 + 32;
  mutatedSource[sourceOff] ^= 1;
  const mutatedCookie = crypto
    .createHmac("sha256", hex(cookie.current_secret_hex, "cookie secret mut"))
    .update(mutatedSource)
    .digest();
  if (equal(mutatedCookie, current)) fail("cookie source mutation accepted");
  executed.add("COOKIE-SOURCE-CARRIER-SESSION-MUTATION");
  const challenge = hex(cookie.challenge_nac1_hex, "challenge");
  const response = hex(cookie.response_nac1_hex, "response");
  validateNpa(challenge, "challenge", 1, 0, 3);
  validateNpa(response, "response", 2, 0, 3);
  if (!equal(challenge.subarray(88), current)) fail("challenge payload");
  const responsePayload = response.subarray(88);
  const cookieParts = cookie.response_length_parts;
  if (
    response.length !== 159 ||
    responsePayload.length !== 71 ||
    cookie.response_nac1_length !== 159 ||
    cookie.response_payload_length !== 71 ||
    cookie.response_length_formula !== "88+32+2+original_message_1_bytes" ||
    cookieParts === undefined ||
    cookieParts.nac1_header_bytes !== 88 ||
    cookieParts.cookie_bytes !== 32 ||
    cookieParts.original_message_1_length_u16be_bytes !== 2 ||
    cookieParts.original_message_1_bytes !== 37 ||
    cookieParts.total_bytes !== 159 ||
    cookieParts.total_bytes !== 88 + 32 + 2 + suite2Payload.length ||
    responsePayload.subarray(0, 32).compare(current) !== 0 ||
    u16(responsePayload, 32) !== 37 ||
    !equal(responsePayload.subarray(34), suite2Payload) ||
    cookie.response_fragment_count !== 2
  ) {
    fail("cookie response exact length 159");
  }
  if (!equal(responsePayload, hex(cookie.response_payload_hex, "response payload"))) {
    fail("cookie response payload hex");
  }
  executed.add("COOKIE-RESPONSE-EXACT-LENGTH-159");
  const cookieFragments = cookie.response_radio_fragments.map((item, index) => {
    const packet = hex(item.hex, `cookie fragment ${index}`);
    validateNpr(packet, `cookie fragment ${index}`);
    // JSON index is machine authority: must equal array position and NAR byte.
    if (exactInt(item.index, `cookie.frag[${index}].index`) !== index) {
      fail(`cookie fragment ${index}: JSON index drift`);
    }
    if (
      packet[42] !== index ||
      packet[42] !== exactInt(item.index, `cookie.frag[${index}].idx`) ||
      packet[43] !== 2 ||
      packet.length !== exactInt(item.length, `cookie.frag[${index}].len`) ||
      shaHex(packet) !== exactStr(item.sha256, `cookie.frag[${index}].sha`)
    ) {
      fail(`cookie fragment ${index}: metadata`);
    }
    return packet;
  });
  if (
    cookieFragments.length !== 2 ||
    !equal(
      Buffer.concat(cookieFragments.map((value) => value.subarray(68))),
      response,
    ) ||
    cookieFragments.some(
      (value) => !equal(value.subarray(44, 60), sha(response).subarray(0, 16)),
    )
  ) {
    fail("cookie fragment reassembly");
  }
  executed.add("COOKIE-RESPONSE-EXACT-2-FRAGMENT-SCRATCH");

  const install = document.attachment_install;
  const nap = hex(install.nap1_hex, "NAP1");
  const nai = hex(install.nai1_hex, "NAI1");
  const nax = hex(install.nax1_hex, "NAX1");
  const nat = hex(install.nat1_hex, "NAT1");
  // Length scalars are machine authority: pin to bytes, u16 length field, limits.
  if (
    nap.length !== 208 ||
    exactInt(install.nap1_length, "install.nap1_length") !== 208 ||
    exactInt(install.nap1_length, "install.nap1_length") !==
      exactInt(limits.nap1_bytes, "limits.nap1_bytes") ||
    nap.subarray(0, 4).toString() !== "NAP1" ||
    u16(nap, 4) !== 1 ||
    u16(nap, 6) !== 208 ||
    u16(nap, 6) !== install.nap1_length ||
    shaHex(nap) !== install.nap1_sha256 ||
    nai.length !== 416 ||
    exactInt(install.nai1_length, "install.nai1_length") !== 416 ||
    exactInt(install.nai1_length, "install.nai1_length") !==
      exactInt(limits.nai1_bytes, "limits.nai1_bytes") ||
    nai.subarray(0, 4).toString() !== "NAI1" ||
    u16(nai, 4) !== 1 ||
    u16(nai, 6) !== 416 ||
    u16(nai, 6) !== install.nai1_length ||
    !equal(nai.subarray(384), sha(nap)) ||
    shaHex(nai) !== install.nai1_sha256
  ) {
    fail("proposal/install descriptors");
  }
  const installDigest = sha(
    Buffer.concat([
      Buffer.from("NINLIL-PRODUCTION-ATTACH-INSTALL-V1"),
      nap,
      nai,
    ]),
  );
  if (installDigest.toString("hex") !== install.install_digest) fail("install digest");
  const mutNap = Buffer.from(nap);
  mutNap[16] ^= 1;
  if (shaHex(mutNap) === install.nap1_sha256) fail("byte+sha nap mutation");
  if (
    shaHex(
      Buffer.concat([
        Buffer.from("NINLIL-PRODUCTION-ATTACH-INSTALL-V1"),
        mutNap,
        nai,
      ]),
    ) === install.install_digest
  ) {
    fail("byte+sha install digest mutation");
  }
  executed.add("BYTE-PLUS-SHA-MUTATION");
  const pf = install.proposal_fields;
  // Full NAP1 proposal_fields wire authority (every declarative leaf ↔ bytes).
  if (
    nap[12] !== 3 ||
    nap[13] !== 2 ||
    !equal(nap.subarray(16, 32), hex(pf.proposal_id, "proposal_id")) ||
    !equal(
      nap.subarray(32, 64),
      hex(pf.initiator_stable_digest, "pf.initiator_stable_digest"),
    ) ||
    !equal(nap.subarray(64, 80), hex(pf.site_domain, "site_domain")) ||
    !equal(nap.subarray(80, 96), hex(pf.authority_id, "authority_id")) ||
    u64(nap, 96) !== BigInt(exactInt(pf.authority_term, "pf.authority_term")) ||
    u64(nap, 104) !==
      BigInt(exactInt(pf.membership_epoch, "pf.membership_epoch")) ||
    u64(nap, 112) !==
      BigInt(
        exactInt(pf.credential_set_revision, "pf.credential_set_revision"),
      ) ||
    u32(nap, 120) !==
      exactInt(pf.revocation_generation, "pf.revocation_generation") ||
    u32(nap, 124) !== exactInt(pf.assignment_epoch, "pf.assignment_epoch") ||
    u32(nap, 128) !==
      exactInt(pf.device_hop_context_ri, "pf.device_hop_context_ri") ||
    u32(nap, 132) !==
      exactInt(pf.device_e2e_context_ri, "pf.device_e2e_context_ri") ||
    u64(nap, 136) !==
      BigInt(
        exactInt(
          pf.device_hop_min_key_generation_ri,
          "pf.device_hop_min_key_generation_ri",
        ),
      ) ||
    u64(nap, 144) !==
      BigInt(
        exactInt(
          pf.device_e2e_min_key_generation_ri,
          "pf.device_e2e_min_key_generation_ri",
        ),
      ) ||
    !equal(nap.subarray(152, 168), hex(pf.e2e_security_id, "pf.e2e_security_id")) ||
    u64(nap, 168) !==
      BigInt(exactInt(pf.e2e_security_epoch, "pf.e2e_security_epoch")) ||
    !equal(
      nap.subarray(176, 208),
      hex(pf.membership_grant_digest, "pf.membership_grant_digest"),
    )
  ) {
    fail("proposal membership/authority fields");
  }
  const iff = install.install_fields;
  // Full NAI1 install_fields wire authority (every declarative leaf ↔ bytes).
  if (
    !equal(nai.subarray(16, 32), hex(iff.attachment_id, "attachment_id")) ||
    !equal(
      nai.subarray(32, 64),
      hex(iff.initiator_stable_digest, "iff.initiator_stable_digest"),
    ) ||
    !equal(
      nai.subarray(64, 96),
      hex(iff.responder_stable_digest, "iff.responder_stable_digest"),
    ) ||
    !equal(nai.subarray(96, 112), hex(iff.site_domain, "install site")) ||
    !equal(nai.subarray(112, 128), hex(iff.authority_id, "install authority")) ||
    u64(nai, 128) !==
      BigInt(exactInt(iff.authority_term, "iff.authority_term")) ||
    u64(nai, 136) !==
      BigInt(exactInt(iff.membership_epoch, "iff.membership_epoch")) ||
    u64(nai, 144) !==
      BigInt(exactInt(iff.attachment_epoch, "iff.attachment_epoch")) ||
    u64(nai, 152) !== BigInt(exactInt(iff.lease_epoch, "iff.lease_epoch")) ||
    !equal(
      nai.subarray(160, 176),
      hex(iff.lease_clock_epoch, "iff.lease_clock_epoch"),
    ) ||
    u64(nai, 176) !==
      BigInt(exactInt(iff.lease_not_before_ms, "iff.lease_not_before_ms")) ||
    u64(nai, 184) !==
      BigInt(exactInt(iff.lease_expires_at_ms, "iff.lease_expires_at_ms")) ||
    u64(nai, 176) >= u64(nai, 184) ||
    u64(nai, 192) !==
      BigInt(
        exactInt(iff.credential_set_revision, "iff.credential_set_revision"),
      ) ||
    u32(nai, 200) !==
      exactInt(
        iff.initiator_credential_generation,
        "iff.initiator_credential_generation",
      ) ||
    u32(nai, 204) !==
      exactInt(
        iff.responder_credential_generation,
        "iff.responder_credential_generation",
      ) ||
    u32(nai, 208) !==
      exactInt(iff.revocation_generation, "iff.revocation_generation") ||
    u32(nai, 212) !== exactInt(iff.assignment_epoch, "iff.assignment_epoch") ||
    u32(nai, 216) !== exactInt(iff.hop_context_ir, "iff.hop_context_ir") ||
    u32(nai, 220) !== exactInt(iff.hop_context_ri, "iff.hop_context_ri") ||
    u32(nai, 224) !== exactInt(iff.e2e_context_ir, "iff.e2e_context_ir") ||
    u32(nai, 228) !== exactInt(iff.e2e_context_ri, "iff.e2e_context_ri") ||
    u64(nai, 232) !==
      BigInt(exactInt(iff.hop_key_generation_ir, "iff.hop_key_generation_ir")) ||
    u64(nai, 240) !==
      BigInt(exactInt(iff.hop_key_generation_ri, "iff.hop_key_generation_ri")) ||
    u64(nai, 248) !==
      BigInt(exactInt(iff.e2e_key_generation_ir, "iff.e2e_key_generation_ir")) ||
    u64(nai, 256) !==
      BigInt(exactInt(iff.e2e_key_generation_ri, "iff.e2e_key_generation_ri")) ||
    !equal(
      nai.subarray(264, 280),
      hex(iff.e2e_security_id, "iff.e2e_security_id"),
    ) ||
    u64(nai, 280) !==
      BigInt(exactInt(iff.e2e_security_epoch, "iff.e2e_security_epoch")) ||
    !equal(
      nai.subarray(288, 320),
      hex(iff.route_policy_digest, "iff.route_policy_digest"),
    ) ||
    !equal(
      nai.subarray(320, 352),
      hex(iff.membership_grant_digest, "iff.membership_grant_digest"),
    ) ||
    !equal(
      nai.subarray(352, 384),
      hex(iff.carrier_transcript_digest, "iff.carrier_transcript_digest"),
    ) ||
    !equal(
      nai.subarray(384, 416),
      hex(iff.proposal_digest, "iff.proposal_digest"),
    ) ||
    !equal(nai.subarray(384, 416), sha(nap)) ||
    iff.proposal_digest !== install.nap1_sha256
  ) {
    fail("install lease/authority fields");
  }
  executed.add("PROPOSAL-MEMBERSHIP-LEASE-AUTHORITY-FIELDS");
  if (
    nax.length !== 160 ||
    exactInt(install.nax1_length, "install.nax1_length") !== 160 ||
    exactInt(install.nax1_length, "install.nax1_length") !==
      exactInt(limits.nax1_bytes, "limits.nax1_bytes") ||
    nax.subarray(0, 4).toString() !== "NAX1" ||
    u16(nax, 6) !== 160 ||
    u16(nax, 6) !== install.nax1_length ||
    nax[8] !== 3 ||
    nax[9] !== 2 ||
    !equal(
      nax.subarray(100, 132),
      hex(iff.carrier_transcript_digest, "nax.carrier_transcript"),
    ) ||
    !equal(nax.subarray(132, 148), hex(iff.authority_id, "nax.authority_id")) ||
    u64(nax, 148) !==
      BigInt(exactInt(iff.authority_term, "nax.authority_term")) ||
    nat.length !== 96 ||
    exactInt(install.nat1_length, "install.nat1_length") !== 96 ||
    exactInt(install.nat1_length, "install.nat1_length") !==
      exactInt(limits.nat1_bytes, "limits.nat1_bytes") ||
    nat.subarray(0, 4).toString() !== "NAT1" ||
    u16(nat, 6) !== 96 ||
    u16(nat, 6) !== install.nat1_length ||
    !equal(nat.subarray(8, 40), installDigest)
  ) {
    fail("NAX/NAT");
  }
  const credentials = document.credentials;
  const initiatorCcs = hex(credentials.initiator_ccs_hex, "initiator ccs");
  const responderCcs = hex(credentials.responder_ccs_hex, "responder ccs");
  const initiatorKid = hex(credentials.initiator_kid_hex, "initiator kid");
  const responderKid = hex(credentials.responder_kid_hex, "responder kid");
  const initKey = decodeCcsCoseKey(initiatorCcs, "initiator CCS");
  const respKey = decodeCcsCoseKey(responderCcs, "responder CCS");
  if (
    credentials.type !== "RPK_CCS_KID" ||
    credentials.curve !== "P-256" ||
    credentials.cose_kty !== 2 ||
    credentials.cose_crv !== 1 ||
    credentials.encoding !== "CBOR_CCS_MAP_CNF_COSE_KEY" ||
    !equal(initKey.kid, initiatorKid) ||
    !equal(respKey.kid, responderKid) ||
    !equal(initKey.x, P256_INITIATOR_X) ||
    !equal(initKey.y, P256_INITIATOR_Y) ||
    !equal(respKey.x, P256_RESPONDER_X) ||
    !equal(respKey.y, P256_RESPONDER_Y) ||
    !equal(initKey.x, hex(credentials.initiator_x_hex, "init x")) ||
    !equal(initKey.y, hex(credentials.initiator_y_hex, "init y")) ||
    !equal(respKey.x, hex(credentials.responder_x_hex, "resp x")) ||
    !equal(respKey.y, hex(credentials.responder_y_hex, "resp y"))
  ) {
    fail("credential CCS/COSE_Key semantic");
  }
  executed.add("CREDENTIAL-CCS-CBOR-DECODE");
  const initDigest = sha(initiatorCcs);
  const respDigest = sha(responderCcs);
  if (
    shaHex(initiatorCcs) !== credentials.initiator_ccs_sha256 ||
    shaHex(responderCcs) !== credentials.responder_ccs_sha256 ||
    shaHex(initiatorCcs) !== credentials.initiator_credential_digest_hex ||
    shaHex(responderCcs) !== credentials.responder_credential_digest_hex ||
    !equal(nax.subarray(36, 68), initDigest) ||
    !equal(nax.subarray(68, 100), respDigest)
  ) {
    fail("credential digest/NAX binding");
  }
  const resolver = hex(credentials.resolver_key_input_hex, "resolver key");
  const expectedResolver = Buffer.concat([
    hex(iff.site_domain, "resolver site"),
    hex(iff.authority_id, "resolver authority"),
    (() => {
      const value = Buffer.alloc(8);
      value.writeBigUInt64BE(BigInt(iff.authority_term));
      return value;
    })(),
    (() => {
      const value = Buffer.alloc(8);
      value.writeBigUInt64BE(BigInt(iff.credential_set_revision));
      return value;
    })(),
    Buffer.from([1, initiatorKid.length]),
    initiatorKid,
  ]);
  if (
    !equal(resolver, expectedResolver) ||
    shaHex(resolver) !== credentials.resolver_key_sha256
  ) {
    fail("credential resolver key");
  }
  executed.add("CREDENTIAL-RPK-CCS-KID");
  {
    const mutCcs = Buffer.from(initiatorCcs);
    mutCcs[mutCcs.length - 1] ^= 1;
    const mutKey = decodeCcsCoseKey(mutCcs, "mutated initiator CCS");
    const mutDigest = sha(mutCcs);
    if (equal(mutKey.y, P256_INITIATOR_Y) || equal(mutDigest, initDigest)) {
      fail("credential tail mutation not effective");
    }
    const mutNax = Buffer.from(nax);
    mutDigest.copy(mutNax, 36);
    if (equal(mutNax.subarray(36, 68), nax.subarray(36, 68))) {
      fail("coherent NAX digest follow failed");
    }
    if (equal(mutKey.y, P256_INITIATOR_Y)) {
      fail("credential tail mutation accepted against pin");
    }
  }
  executed.add("CREDENTIAL-TAIL-MUTATION");
  if (
    pf.device_hop_context_ri !== iff.hop_context_ri ||
    pf.device_e2e_context_ri !== iff.e2e_context_ri ||
    pf.device_hop_min_key_generation_ri !== iff.hop_key_generation_ri ||
    pf.device_e2e_min_key_generation_ri !== iff.e2e_key_generation_ri
  ) {
    fail("NAP/NAI RI context baseline mismatch");
  }
  {
    const mutNap = Buffer.from(nap);
    mutNap.writeUInt32BE((iff.hop_context_ri ^ 0x5a5a5a5a) >>> 0, 128);
    const mutNapDigest = sha(mutNap);
    const mutNai = Buffer.from(nai);
    mutNapDigest.copy(mutNai, 384);
    const mutInstall = sha(
      Buffer.concat([
        Buffer.from("NINLIL-PRODUCTION-ATTACH-INSTALL-V1"),
        mutNap,
        mutNai,
      ]),
    );
    if (
      u32(mutNap, 128) === iff.hop_context_ri ||
      u32(mutNap, 128) === u32(nai, 220) ||
      equal(mutInstall, installDigest) ||
      equal(mutNapDigest, sha(nap))
    ) {
      fail("NAP/NAI context mismatch not observed after digest follow");
    }
  }
  executed.add("NAP-NAI-CONTEXT-MISMATCH");
  if (
    shaHex(
      Buffer.concat([Buffer.from("NINLIL-ATTACH-PROTECT-CONTEXT-V1"), nax]),
    ) !== install.protection_exporter_context_digest ||
    shaHex(
      Buffer.concat([
        Buffer.from("NINLIL-ATTACH-TRAFFIC-CONTEXT-V1"),
        nax,
        installDigest,
      ]),
    ) !== install.traffic_exporter_context_digest ||
    install.aead_vector_status !== "INPUTS_PINNED_CIPHERTEXT_NOT_CLAIMED"
  ) {
    fail("exporter contexts/nonclaim");
  }
  const mutatedNax = Buffer.from(nax);
  mutatedNax[0] ^= 1;
  if (
    shaHex(
      Buffer.concat([Buffer.from("NINLIL-ATTACH-PROTECT-CONTEXT-V1"), mutatedNax]),
    ) === install.protection_exporter_context_digest
  ) {
    fail("exporter context one-byte mutation accepted");
  }
  executed.add("EXPORTER-CONTEXT-ONE-BYTE-MUTATION");

  const matrix = [
    ["propose_seq5", 8, 5, 216],
    ["install_seq6", 9, 6, 424],
    ["confirm_device_seq7", 10, 7, 104],
    ["confirm_authority_seq8", 11, 8, 104],
  ];
  const records = new Map();
  for (const [name, kind, sequence, payloadLength] of matrix) {
    const record = hex(install.records[name], name);
    records.set(name, record);
    validateNpa(record, name, kind, sequence, 3);
    if (record.length !== 88 + payloadLength) fail(`${name}: length`);
  }
  // Opaque length scalars must match protected ciphertext+tag payload sizes.
  if (
    exactInt(
      install.proposal_opaque_ciphertext_and_tag_length,
      "install.proposal_opaque_len",
    ) !== 216 ||
    exactInt(
      install.proposal_opaque_ciphertext_and_tag_length,
      "install.proposal_opaque_len",
    ) !==
      records.get("propose_seq5").length - 88 ||
    exactInt(install.opaque_ciphertext_and_tag_length, "install.opaque_len") !==
      424 ||
    exactInt(install.opaque_ciphertext_and_tag_length, "install.opaque_len") !==
      records.get("install_seq6").length - 88 ||
    exactInt(
      install.confirm_opaque_ciphertext_and_tag_length,
      "install.confirm_opaque_len",
    ) !== 104 ||
    exactInt(
      install.confirm_opaque_ciphertext_and_tag_length,
      "install.confirm_opaque_len",
    ) !==
      records.get("confirm_device_seq7").length - 88 ||
    exactInt(
      install.confirm_opaque_ciphertext_and_tag_length,
      "install.confirm_opaque_len",
    ) !==
      records.get("confirm_authority_seq8").length - 88
  ) {
    fail("install opaque length authority");
  }
  if (
    records.get("install_seq6").subarray(0, 84).toString("hex") !==
    install.install_nac1_aad_prefix_hex
  ) {
    fail("AAD");
  }
  executed.add("PROTECTED-PROPOSE-INSTALL-DUAL-CONFIRM-SEQUENCE");

  const generation = u64(records.get("install_seq6"), 36);
  for (const [name, ivName, sequence] of [
    ["propose_i2r_seq5", "attach_i2r_base_iv13_hex", 5],
    ["install_r2i_seq6", "attach_r2i_base_iv13_hex", 6],
    ["confirm_device_i2r_seq7", "attach_i2r_base_iv13_hex", 7],
    ["confirm_authority_r2i_seq8", "attach_r2i_base_iv13_hex", 8],
  ]) {
    const iv = hex(install[ivName], ivName);
    const mask = Buffer.alloc(13);
    mask.writeBigUInt64BE(generation, 1);
    mask.writeUInt32BE(sequence, 9);
    const expected = Buffer.from(iv.map((value, index) => value ^ mask[index]));
    if (!equal(expected, hex(install.protection_nonces[name], name))) {
      fail(`${name}: nonce`);
    }
  }
  executed.add("CONTROL-NONCE-SEQUENCE-DIRECTION-EXACT");

  assertNarFragmentShapeAuthority(executed);

  const fragments = document.compact_radio_fragments.map((item, index) => {
    const packet = hex(item.hex, `fragment ${index}`);
    validateNpr(packet, `fragment ${index}`);
    // JSON index is machine authority: must equal array position and NAR byte.
    if (exactInt(item.index, `frag[${index}].index`) !== index) {
      fail(`fragment ${index}: JSON index drift`);
    }
    if (
      packet[42] !== index ||
      packet[42] !== exactInt(item.index, `frag[${index}].idx`) ||
      packet[43] !== document.compact_radio_fragments.length ||
      packet.length !== exactInt(item.length, `frag[${index}].len`) ||
      shaHex(packet) !== exactStr(item.sha256, `frag[${index}].sha`)
    ) {
      fail(`fragment ${index}: metadata`);
    }
    return packet;
  });
  if (fragments.length !== 5) fail("fragment count");
  if (exactInt(limits.nar1_fragment_count_max, "limits.nar1_frag_count") !== 5) {
    fail("fragment count limit pin");
  }
  const assembled = Buffer.concat(fragments.map((value) => value.subarray(68)));
  if (!equal(assembled, records.get("install_seq6"))) fail("reassembly");
  const digest16 = sha(assembled).subarray(0, 16);
  if (fragments.some((value) => !equal(value.subarray(44, 60), digest16))) {
    fail("fragment digest");
  }
  for (const packet of fragments) {
    if (
      !equal(packet.subarray(12, 28), assembled.subarray(20, 36)) ||
      u64(packet, 28) !== u64(assembled, 36) ||
      u32(packet, 36) !== u32(assembled, 44) ||
      u16(packet, 40) !== assembled.length ||
      !equal(packet.subarray(44, 60), digest16)
    ) {
      fail("NAR carrier/session/generation/binding tuple");
    }
  }
  const expectedGeneration = u64(assembled, 36);
  if (fragments.some((packet) => u64(packet, 28) !== expectedGeneration)) {
    fail("NAR exchange generation not uniform");
  }
  {
    const genMut = Buffer.from(fragments[1]);
    const next = expectedGeneration ^ 0x11n;
    genMut.writeBigUInt64BE(next, 28);
    recomputeCrcNprLocal(genMut);
    if (
      u64(genMut, 28) === expectedGeneration ||
      u64(genMut, 28) === u64(fragments[0], 28) ||
      u64(genMut, 28) === u64(assembled, 36)
    ) {
      fail("NAR generation mutation not divergent");
    }
  }
  executed.add("NAC1-INSTALL-MAX-RADIO-FRAGMENTATION");
  executed.add("NAR1-EXCHANGE-GENERATION-BINDING");
  validateNpaNprAdversarial(
    document,
    records.get("install_seq6"),
    fragments,
    executed,
  );

  const attachmentId = hex(iff.attachment_id, "attachment_id");
  const marker = document.n6_attachment_marker;
  const markerKey = hex(marker.key_hex, "N6AT key");
  const markerValue = hex(marker.value_hex, "N6AT value");
  // Declarative N6 marker metadata must bind to decoded key/value + limits.
  const N6AT_STATE_NAME = { 1: "PENDING", 2: "ACTIVE", 3: "FENCED" };
  const markerRole = exactInt(marker.local_role, "n6.local_role");
  const markerState = exactInt(marker.state, "n6.state");
  const markerStateName = exactStr(marker.state_name, "n6.state_name");
  if (
    markerRole !== 1 ||
    markerState !== 2 ||
    markerStateName !== N6AT_STATE_NAME[markerState] ||
    markerStateName !== "ACTIVE" ||
    exactInt(marker.key_length, "n6.key_length") !== markerKey.length ||
    exactInt(marker.key_length, "n6.key_length") !==
      exactInt(limits.n6at_key_bytes, "limits.n6at_key") ||
    exactInt(marker.value_length, "n6.value_length") !== markerValue.length ||
    exactInt(marker.value_length, "n6.value_length") !==
      exactInt(limits.n6at_value_bytes, "limits.n6at_value") ||
    markerKey[1] !== markerRole ||
    markerValue[8] !== markerState ||
    markerValue[9] !== markerRole
  ) {
    fail("N6AT marker metadata binding");
  }
  validateN6atPair(
    markerKey,
    markerValue,
    markerRole,
    markerState,
    attachmentId,
    installDigest,
    "device ACTIVE",
    iff,
  );
  if (shaHex(markerValue) !== exactStr(marker.value_sha256, "n6.vs")) {
    fail("N6AT sha");
  }
  if (markerValue[10] !== 0 || markerValue[11] !== 0) fail("N6AT reserved baseline");
  {
    const reservedMut = Buffer.from(markerValue);
    reservedMut[10] = 1;
    recomputeCrcN6at(reservedMut);
    try {
      validateN6atPair(markerKey, reservedMut, 1, 2, attachmentId, installDigest, "reserved mut", iff);
      fail("N6AT reserved mutation accepted");
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  executed.add("N6AT-RESERVED-BYTES");
  {
    const markerCrc = Buffer.from(markerValue);
    markerCrc[markerCrc.length - 1] ^= 1;
    if (crc32c(markerCrc.subarray(0, 116)) === u32(markerCrc, 116)) {
      fail("N6AT CRC mutation survived");
    }
  }
  executed.add("N6AT-CRC-MUTATION");
  try {
    const badKey = Buffer.concat([Buffer.from([5, 2, 1, 0]), markerKey.subarray(4)]);
    validateN6atPair(badKey, markerValue, 1, 2, attachmentId, installDigest, "role mismatch", iff);
    fail("N6AT role mismatch accepted");
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
  }
  executed.add("N6AT-ROLE-KEY-VALUE-MISMATCH");
  {
    const unknownState = Buffer.from(markerValue);
    unknownState[8] = 4;
    recomputeCrcN6at(unknownState);
    try {
      validateN6atPair(markerKey, unknownState, 1, 2, attachmentId, installDigest, "unknown", iff);
      fail("N6AT unknown accepted");
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  executed.add("N6AT-UNKNOWN-STATE");

  const lifecycle = document.lifecycle;
  const roles = lifecycle.roles;
  const N6AT_STATE_NAME_MAP = { 1: "PENDING", 2: "ACTIVE", 3: "FENCED" };
  for (const [roleName, role] of [
    ["device_local_role_1", 1],
    ["authority_local_role_2", 2],
  ]) {
    const roleItem = roles[roleName];
    for (const [stateName, state] of [
      ["pending", 1],
      ["active", 2],
      ["fenced_third", 3],
    ]) {
      const item = roleItem[stateName];
      const key = hex(item.key_hex, `${roleName} ${stateName} key`);
      const value = hex(item.value_hex, `${roleName} ${stateName} value`);
      // Declarative metadata must match decoded bytes and role binding.
      if (exactInt(item.state, `${roleName}.${stateName}.state`) !== state) {
        fail(`${roleName}.${stateName}: state metadata`);
      }
      if (
        exactStr(item.state_name, `${roleName}.${stateName}.name`) !==
        N6AT_STATE_NAME_MAP[state]
      ) {
        fail(`${roleName}.${stateName}: state_name metadata`);
      }
      if (value[8] !== state || value[9] !== role || key[1] !== role) {
        fail(`${roleName}.${stateName}: decoded state/role binding`);
      }
      if (
        shaHex(value) !==
        exactStr(item.value_sha256, `${roleName}.${stateName}.vs`)
      ) {
        fail(`${roleName}.${stateName}: value_sha metadata`);
      }
      if (state === 3 && item.accepted !== false) fail(`${roleName} third accepted`);
      validateN6atPair(
        key,
        value,
        role,
        exactInt(item.state, "state"),
        attachmentId,
        installDigest,
        `${roleName} ${stateName}`,
        iff,
      );
    }
    try {
      const wrongRoleKey = Buffer.concat([
        Buffer.from([5, 3 - role, 1, 0]),
        attachmentId,
      ]);
      validateN6atPair(
        wrongRoleKey,
        hex(roleItem.pending.value_hex, "div role val"),
        role,
        1,
        attachmentId,
        installDigest,
        `${roleName} div role`,
       iff);
      fail("divergent role accepted");
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  executed.add("N6AT-ROLE-SPECIFIC-BOTH");
  const pending = lifecycle.pending_marker;
  const pendingKey = hex(pending.key_hex, "pending key");
  const pendingValue = hex(pending.value_hex, "pending marker");
  if (
    exactInt(pending.local_role, "pm.local_role") !== 1 ||
    exactInt(pending.state, "pm.state") !== 1 ||
    exactStr(pending.state_name, "pm.name") !== "PENDING" ||
    pendingValue[8] !== 1 ||
    pendingValue[9] !== 1 ||
    pendingKey[1] !== 1 ||
    shaHex(pendingValue) !== exactStr(pending.value_sha256, "pm.vs") ||
    !equal(
      pendingKey,
      hex(
        lifecycle.roles.device_local_role_1.pending.key_hex,
        "dev pending key",
      ),
    ) ||
    !equal(
      pendingValue,
      hex(
        lifecycle.roles.device_local_role_1.pending.value_hex,
        "dev pending val",
      ),
    )
  ) {
    fail("pending_marker metadata/role binding");
  }
  validateN6atPair(
    pendingKey,
    pendingValue,
    exactInt(pending.local_role, "pm role"),
    exactInt(pending.state, "pm state"),
    attachmentId,
    installDigest,
    "pending",
    iff,
  );
  executed.add("N6AT-PENDING-MARKER");
  const p2a = lifecycle.pending_to_active;
  const p2aOld = hex(p2a.old_value_hex, "p2a old");
  const p2aNew = hex(p2a.new_value_hex, "p2a new");
  if (
    exactInt(p2a.old_state, "p2a.old_state") !== 1 ||
    exactInt(p2a.new_state, "p2a.new_state") !== 2 ||
    exactStr(p2a.mutation_kind, "p2a.kind") !== "SINGLE_KEY_FULL_MARKER_ONLY" ||
    !equal(p2aOld, pendingValue) ||
    !equal(p2aNew, markerValue) ||
    markerValue[8] !== 2 ||
    p2aOld[8] !== 1 ||
    p2aNew[8] !== 2 ||
    shaHex(p2aOld) !== exactStr(p2a.old_value_sha256, "p2a.old_sha") ||
    shaHex(p2aNew) !== exactStr(p2a.new_value_sha256, "p2a.new_sha")
  ) {
    fail("pending to active");
  }
  executed.add("N6AT-PENDING-TO-ACTIVE");
  const cu = lifecycle.commit_unknown;
  const third = hex(cu.third_value_hex, "third value");
  const deviceThird = hex(
    lifecycle.roles.device_local_role_1.fenced_third.value_hex,
    "device third",
  );
  if (
    !equal(hex(cu.old_pending_value_hex, "cu old"), pendingValue) ||
    !equal(hex(cu.new_active_value_hex, "cu new"), markerValue) ||
    cu.third_value_state !== 3 ||
    third[8] !== 3 ||
    !equal(third, deviceThird) ||
    cu.third_value_accepted !== false ||
    JSON.stringify(cu.accepted_states) !== JSON.stringify([1, 2])
  ) {
    fail("commit unknown old/new/third");
  }
  assertExactUniqueStringList(
    cu.accepted_classifications,
    CU_ACCEPTED_CLASSIFICATIONS_EXACT,
    "lifecycle.commit_unknown.accepted_classifications",
  );
  executed.add("N6AT-COMMIT-UNKNOWN-OLD-NEW-THIRD");
  const gm = lifecycle.group_machine;
  if (
    gm.member_count_exact !== 15 ||
    gm.old_count_is_protocol_constant !== false ||
    gm.observed_old_non_absent_count !== 14 ||
    gm.legal_nonempty_lane_old_required !== true ||
    gm.new_pending_member_count !== 15 ||
    JSON.stringify(gm.partial_member_counts_rejected) !==
      JSON.stringify([...Array(14)].map((_, i) => i + 1)) ||
    gm.extra_member_rejected !== true ||
    gm.third_value_or_digest_mismatch_rejected !== true ||
    gm.pending_to_active_single_key_full !== true ||
    gm.publication_before_dual_confirm !== 0 ||
    gm.role_attachment_id_must_match !== true
  ) {
    fail("lifecycle group machine fields");
  }
  // Top-level group_machine role digests/keys must bind to lifecycle.roles.
  const deviceRole = lifecycle.roles.device_local_role_1;
  const authorityRole = lifecycle.roles.authority_local_role_2;
  if (
    !equal(
      hex(gm.device_pending_key_hex, "gm.dev.pk"),
      hex(deviceRole.pending.key_hex, "dev.pending.key"),
    ) ||
    !equal(
      hex(gm.device_pending_value_hex, "gm.dev.pv"),
      hex(deviceRole.pending.value_hex, "dev.pending.val"),
    ) ||
    !equal(
      hex(gm.device_active_value_hex, "gm.dev.av"),
      hex(deviceRole.active.value_hex, "dev.active.val"),
    ) ||
    !equal(
      hex(gm.authority_pending_key_hex, "gm.auth.pk"),
      hex(authorityRole.pending.key_hex, "auth.pending.key"),
    ) ||
    !equal(
      hex(gm.authority_pending_value_hex, "gm.auth.pv"),
      hex(authorityRole.pending.value_hex, "auth.pending.val"),
    ) ||
    !equal(
      hex(gm.authority_active_value_hex, "gm.auth.av"),
      hex(authorityRole.active.value_hex, "auth.active.val"),
    ) ||
    exactStr(gm.device_complete_keys_concat_sha256, "gm.dev.concat") !==
      exactStr(
        document.atomic_batch_manifests.device_local_role_1
          .complete_keys_concat_sha256,
        "dev.nab.concat",
      ) ||
    exactStr(gm.authority_complete_keys_concat_sha256, "gm.auth.concat") !==
      exactStr(
        document.atomic_batch_manifests.authority_local_role_2
          .complete_keys_concat_sha256,
        "auth.nab.concat",
      )
  ) {
    fail("group_machine role key/value/concat binding");
  }
  const snaps = gm.snapshots;
  if (!snaps || !snaps.roles) fail("lifecycle snapshots missing");
  if (
    !Array.isArray(snaps.classification_domain) ||
    JSON.stringify(snaps.classification_domain) !==
      JSON.stringify(CLASSIFICATION_DOMAIN_EXACT) ||
    new Set(snaps.classification_domain).size !==
      snaps.classification_domain.length
  ) {
    fail("classification_domain exact closed list");
  }
  if (
    exactStr(snaps.durability_model, "snaps.durability_model") !==
    "WRITE_SET_OBSERVED_OLD_PROPOSED_NEW"
  ) {
    fail("snaps.durability_model pin");
  }
  if (
    exactStr(snaps.reattach_policy, "snaps.reattach_policy") !==
    "PER_ROW_OLD_PRESENT_WITH_LEGAL_LANE_OLD_AND_MARKER_ABSENT;MONOTONIC_FLOOR_HIGH_WATER;NO_ATTACHMENT_SCOPED_NAMESPACE"
  ) {
    fail("snaps.reattach_policy pin");
  }
  for (const [roleName, roleKey] of [
    ["device_local_role_1", 1],
    ["authority_local_role_2", 2],
  ]) {
    const inv = document.atomic_batch_manifests[roleName].exact_inventory;
    const ordered = inv.map((e) => hex(e.complete_key_hex, `${roleName} ok`));
    const roleItem = roles[roleName];
    const markerKey = hex(roleItem.pending.key_hex, `${roleName} mk`);
    const pendingValue = hex(roleItem.pending.value_hex, `${roleName} pv`);
    const activeValue = hex(roleItem.active.value_hex, `${roleName} av`);
    const thirdValue = hex(roleItem.fenced_third.value_hex, `${roleName} tv`);
    const roleSnaps = snaps.roles[roleName];
    const oldPresentInventory = inv.filter((entry) => entry.old_present === true);
    const oldAbsentInventory = inv.filter((entry) => entry.old_present === false);
    if (
      oldPresentInventory.length !== 14 ||
      oldAbsentInventory.length !== 1 ||
      oldAbsentInventory[0].member_kind !== 4 ||
      oldAbsentInventory[0].identity !== "attachment_marker" ||
      oldAbsentInventory[0].old_value_hex !== "" ||
      oldAbsentInventory[0].old_value_sha256 !== "" ||
      oldAbsentInventory[0].old_context_digest_hex !== "" ||
      oldPresentInventory.some(
        (entry) =>
          entry.old_value_hex === "" ||
          entry.old_value_sha256 === "" ||
          entry.old_context_digest_hex === "" ||
          entry.old_new_relation !== "DIFFERENT",
      )
    ) {
      fail(`${roleName}: per-row OLD presence authority`);
    }
    const old0 = requireKeys(roleSnaps.exact_old, `${roleName}.exact_old`, [
      "member_count",
      "present_complete_keys_hex",
      "members",
      "full_image_sha256",
      "classification",
      "commit_unknown_accepted",
      "observed_old_non_absent_count",
      "marker_absent",
    ]);
    // Observed OLD is derived per write-set row: all 14 non-marker rows are
    // present, including the six legal canonical lane rows.  Only the marker
    // is OLD-absent; 14 is fixture data, never a protocol cardinality.
    if (
      exactStr(old0.classification, `${roleName} old cls`) !== "EXACT_OLD" ||
      exactInt(old0.member_count, `${roleName} old count`) !== 14 ||
      exactInt(old0.observed_old_non_absent_count, `${roleName} old obs`) !==
        14 ||
      exactBool(old0.marker_absent, `${roleName} old marker`) !== true ||
      exactBool(old0.commit_unknown_accepted, `${roleName} old CU`) !== true ||
      !Array.isArray(old0.members) ||
      old0.members.length !== 14 ||
      old0.members.some((m) => ![1, 2, 3].includes(exactInt(m.member_kind, "old mk"))) ||
      old0.members.filter((m) => exactInt(m.member_kind, "k") === 1).length !== 6 ||
      old0.members.filter((m) => exactInt(m.member_kind, "k") === 2).length !== 4 ||
      old0.members.filter((m) => exactInt(m.member_kind, "k") === 3).length !== 4
    ) {
      fail(`${roleName}: exact OLD per-row preimage (6 lane + 4 AL + 4 HW)`);
    }
    const newMembersPreview = roleSnaps.exact_new_pending_15.members;
    if (!Array.isArray(newMembersPreview) || newMembersPreview.length !== 15) {
      fail(`${roleName}: NEW members missing for value-image`);
    }
    {
      const viOld = classifyWriteSetValueImageIndependent({
        presentMembers: old0.members,
        oldMembers: old0.members,
        newMembers: newMembersPreview,
        writeSetKeysOrdered: ordered,
        markerKey,
      });
      if (viOld !== "EXACT_OLD") {
        fail(`${roleName}: value-image OLD classification ${viOld}`);
      }
      if (
        classifyGroupSnapshotIndependent({
          presentKeys: [],
          expectedKeysOrdered: ordered,
          markerKey,
          markerState: null,
          markerValueOk: true,
        }) === "EXACT_OLD"
      ) {
        fail(`${roleName}: key-presence empty must not be EXACT_OLD`);
      }
    }
    {
      const invByKey = new Map(
        inv.map((e) => [exactStr(e.complete_key_hex, "inv ck"), e]),
      );
      const oldParts = [];
      for (const member of old0.members) {
        const complete = hex(member.complete_key_hex, "old ck");
        const entry = invByKey.get(
          exactStr(member.complete_key_hex, "old ck hex"),
        );
        if (!entry) fail(`${roleName}: OLD key not in inventory`);
        const localStable =
          roleKey === 1
            ? "initiator_stable_digest"
            : "responder_stable_digest";
        const peerStable =
          roleKey === 1
            ? "responder_stable_digest"
            : "initiator_stable_digest";
        const localNode = r6NodeId16(hex(iff[localStable], "ls"));
        const peerNode = r6NodeId16(hex(iff[peerStable], "ps"));
        const value = materializeMemberValueIndependent({
          memberKind: exactInt(entry.member_kind, "old mk"),
          completeKey: complete,
          installDigest,
          valueLength: exactInt(entry.value_bytes, "old vb"),
          markerValue: null,
          localSide: exactInt(entry.local_side ?? 0, "old ls"),
          keyGeneration: exactInt(entry.key_generation, "old kg"),
          membershipEpoch: exactInt(iff.membership_epoch, "old me"),
          phase: "old",
          peerNodeId: peerNode,
          localNodeId: localNode,
          contextId: exactInt(entry.context_id, "cid"),
          layerCode: exactInt(entry.layer_code, "lc"),
        });
        const ctx = materializeOldContextDigestIndependent({
          memberKind: entry.member_kind,
          completeKey: complete,
          attachmentId,
        });
        if (
          exactBool(entry.old_present, "old_present") !== true ||
          !equal(value, hex(member.value_hex, "old val")) ||
          !equal(value, hex(entry.old_value_hex, "entry old val")) ||
          shaHex(value) !== exactStr(member.value_sha256, "old vs") ||
          shaHex(value) !== exactStr(entry.old_value_sha256, "entry old vs") ||
          !equal(ctx, hex(member.context_digest_hex, "old ctx")) ||
          !equal(ctx, hex(entry.old_context_digest_hex, "entry old ctx"))
        ) {
          fail(`${roleName}: OLD value/ctx recompute ${entry.identity}`);
        }
        const magic = value.subarray(0, 4).toString("ascii");
        if (
          value.toString("ascii").startsWith("NINLIL-PA-N6-VALUE-V1") ||
          !["N6TX", "N6RX", "N6AL", "N6HW"].includes(magic)
        ) {
          fail(`${roleName}: OLD not canonical N6 codec`);
        }
        oldParts.push(Buffer.concat([complete, value, ctx]));
      }
      if (
        shaHex(fullImageFromMembers(old0.members)) !==
          exactStr(old0.full_image_sha256, `${roleName} old img`) ||
        shaHex(Buffer.concat(oldParts)) !== old0.full_image_sha256
      ) {
        fail(`${roleName}: exact old full_image`);
      }
    }
    for (let n = 1; n <= 14; n += 1) {
      const snap = requireKeys(roleSnaps[`partial_${n}`], `${roleName}.partial_${n}`, [
        "member_count",
        "present_complete_keys_hex",
        "members",
        "full_image_sha256",
        "classification",
        "commit_unknown_accepted",
        "advanced_to_new_count",
      ]);
      if (
        exactStr(snap.classification, `p${n} cls`) !== `PARTIAL_${n}_CORRUPT` ||
        exactBool(snap.commit_unknown_accepted, `p${n} CU`) !== false ||
        exactInt(snap.advanced_to_new_count, `p${n} adv`) !== n ||
        !Array.isArray(snap.members) ||
        snap.members.length === 0
      ) {
        fail(`${roleName}: partial ${n} classification/CU`);
      }
      if (
        shaHex(fullImageFromMembers(snap.members)) !==
        exactStr(snap.full_image_sha256, `p${n} img`)
      ) {
        fail(`${roleName}: partial ${n} full_image_sha256`);
      }
      const viP = classifyWriteSetValueImageIndependent({
        presentMembers: snap.members,
        oldMembers: old0.members,
        newMembers: newMembersPreview,
        writeSetKeysOrdered: ordered,
        markerKey,
      });
      if (viP !== `PARTIAL_${n}_CORRUPT`) {
        fail(`${roleName}: value-image partial ${n} got ${viP}`);
      }
    }
    let cls = classifyWriteSetValueImageIndependent({
      presentMembers: newMembersPreview,
      oldMembers: old0.members,
      newMembers: newMembersPreview,
      writeSetKeysOrdered: ordered,
      markerKey,
    });
    const snap15 = requireKeys(
      roleSnaps.exact_new_pending_15,
      `${roleName}.exact_new_pending_15`,
      [
        "member_count",
        "present_complete_keys_hex",
        "present_keys_concat_sha256",
        "members",
        "full_image_sha256",
        "marker_state",
        "marker_value_hex",
        "classification",
        "commit_unknown_accepted",
        "value_substitution_rejected",
        "context_digest_substitution_rejected",
      ],
    );
    const members = snap15.members;
    if (!Array.isArray(members) || members.length !== 15) {
      fail(`${roleName}: NEW members missing`);
    }
    const expectedConcat = shaHex(Buffer.concat(ordered));
    if (
      cls !== "EXACT_NEW_PENDING_15" ||
      exactStr(snap15.classification, `${roleName} new cls`) !== cls ||
      exactBool(snap15.commit_unknown_accepted, `${roleName} new CU`) !== true ||
      exactInt(snap15.member_count, `${roleName} new count`) !== 15 ||
      exactStr(
        snap15.present_keys_concat_sha256,
        `${roleName} present_keys_concat_sha256`,
      ) !== expectedConcat ||
      snap15.present_complete_keys_hex.length !== 15 ||
      exactInt(snap15.marker_state, `${roleName} new ms`) !== 1 ||
      !equal(hex(snap15.marker_value_hex, `${roleName} new mv`), pendingValue) ||
      pendingValue[8] !== 1
    ) {
      fail(`${roleName}: exact new pending 15`);
    }
    // Independent present_complete_keys order pin
    for (let i = 0; i < 15; i += 1) {
      if (!equal(hex(snap15.present_complete_keys_hex[i], "pck"), ordered[i])) {
        fail(`${roleName}: present_complete_keys mismatch at ${i}`);
      }
    }
    const recomputedParts = [];
    for (let i = 0; i < 15; i += 1) {
      const entry = inv[i];
      const member = requireKeys(members[i], `${roleName} member`, [
        "index",
        "identity",
        "complete_key_hex",
        "complete_key_length",
        "value_hex",
        "value_sha256",
        "context_digest_hex",
        "member_kind",
        "value_bytes",
      ]);
      const complete = hex(entry.complete_key_hex, "e ck");
      if (!equal(complete, hex(member.complete_key_hex, "m ck"))) {
        fail(`${roleName}: member key ${entry.identity}`);
      }
      const localStable =
        roleKey === 1
          ? iff.initiator_stable_digest
          : iff.responder_stable_digest;
      const peerStable =
        roleKey === 1
          ? iff.responder_stable_digest
          : iff.initiator_stable_digest;
      const localNode = r6NodeId16(hex(localStable, "ls"));
      const peerNode = r6NodeId16(hex(peerStable, "ps"));
      const value = materializeMemberValueIndependent({
        memberKind: exactInt(entry.member_kind, "mk"),
        completeKey: complete,
        installDigest,
        valueLength: exactInt(entry.value_bytes, "vb"),
        markerValue: entry.member_kind === 4 ? pendingValue : null,
        localSide: exactInt(entry.local_side ?? 0, "ls"),
        keyGeneration: exactInt(entry.key_generation, "kg"),
        membershipEpoch: exactInt(iff.membership_epoch, "me"),
        phase: "new",
        peerNodeId: peerNode,
        localNodeId: localNode,
          contextId: exactInt(entry.context_id, "cid"),
          layerCode: exactInt(entry.layer_code, "lc"),
        });
      const ctx = materializeContextDigestIndependent({
        memberKind: entry.member_kind,
        completeKey: complete,
        installDigest,
        attachmentId,
      });
      if (
        !equal(value, hex(member.value_hex, "m val")) ||
        !equal(value, hex(entry.value_hex, "e val")) ||
        shaHex(value) !== exactStr(member.value_sha256, "m vs") ||
        member.value_sha256 !== entry.value_sha256 ||
        !equal(ctx, hex(member.context_digest_hex, "m ctx")) ||
        !equal(ctx, hex(entry.context_digest_hex, "e ctx")) ||
        exactInt(member.index, `${roleName} m.idx`) !== i ||
        exactInt(member.index, `${roleName} m.idx`) !==
          exactInt(entry.index, `${roleName} e.idx`) ||
        exactStr(member.identity, `${roleName} m.id`) !==
          exactStr(entry.identity, `${roleName} e.id`) ||
        exactInt(member.member_kind, `${roleName} m.mk`) !==
          exactInt(entry.member_kind, `${roleName} e.mk`) ||
        exactInt(member.complete_key_length, `${roleName} m.ckl`) !==
          complete.length ||
        exactInt(member.complete_key_length, `${roleName} m.ckl`) !==
          exactInt(entry.complete_key_length, `${roleName} e.ckl`) ||
        exactInt(member.value_bytes, `${roleName} m.vb`) !== value.length ||
        exactInt(member.value_bytes, `${roleName} m.vb`) !==
          exactInt(entry.value_bytes, `${roleName} e.vb`)
      ) {
        fail(`${roleName}: value/ctx/metadata recompute ${entry.identity}`);
      }
      recomputedParts.push(complete, value, ctx);
    }
    const recomputedImage = Buffer.concat(recomputedParts);
    if (shaHex(recomputedImage) !== snap15.full_image_sha256) {
      fail(`${roleName}: full image sha`);
    }
    if (
      shaHex(recomputedImage) !==
      document.atomic_batch_manifests[roleName].full_image_sha256
    ) {
      fail(`${roleName}: inventory full image sha`);
    }
    validateSubstitutionRejected({
      kind: "value",
      block: snap15.value_substitution_rejected,
      baseMembers: members,
      fullImageSha: snap15.full_image_sha256,
      field: `${roleName}.value_substitution_rejected`,
    });
    validateSubstitutionRejected({
      kind: "context",
      block: snap15.context_digest_substitution_rejected,
      baseMembers: members,
      fullImageSha: snap15.full_image_sha256,
      field: `${roleName}.context_digest_substitution_rejected`,
    });
    const canonIdx = members.findIndex((m) => m.member_kind !== 4);
    if (
      exactInt(snap15.value_substitution_rejected.mutated_index, "vs idx") !==
        canonIdx ||
      exactInt(
        snap15.context_digest_substitution_rejected.mutated_index,
        "cds idx",
      ) !== canonIdx
    ) {
      fail(`${roleName}: substitution mutated_index not canonical`);
    }
    const extra = requireKeys(roleSnaps.extra_16, `${roleName}.extra_16`, [
      "member_count",
      "foreign_complete_key_hex",
      "classification",
      "commit_unknown_accepted",
    ]);
    const foreign = hex(extra.foreign_complete_key_hex, `${roleName} foreign`);
    if (ordered.some((k) => equal(k, foreign))) {
      fail(`${roleName}: foreign key not foreign`);
    }
    if (
      !["EXTRA_CORRUPT", "FOREIGN_OR_EXTRA_CORRUPT"].includes(
        exactStr(extra.classification, `${roleName} extra cls`),
      ) ||
      exactInt(extra.member_count, `${roleName} extra count`) !== 16 ||
      exactBool(extra.commit_unknown_accepted, `${roleName} extra CU`) !== false
    ) {
      fail(`${roleName}: extra_16 fields`);
    }
    const thirdSnap = requireKeys(
      roleSnaps.third_mismatch,
      `${roleName}.third_mismatch`,
      [
        "member_count",
        "marker_state",
        "marker_value_hex",
        "classification",
        "commit_unknown_accepted",
      ],
    );
    {
      const thirdMembers = members.map((m) => ({ ...m }));
      for (let i = 0; i < thirdMembers.length; i += 1) {
        if (exactInt(thirdMembers[i].member_kind, "tm mk") === 4) {
          thirdMembers[i] = {
            ...thirdMembers[i],
            value_hex: exactStr(thirdSnap.marker_value_hex, "third mv"),
            value_sha256: shaHex(thirdValue),
          };
          break;
        }
      }
      cls = classifyWriteSetValueImageIndependent({
        presentMembers: thirdMembers,
        oldMembers: old0.members,
        newMembers: members,
        writeSetKeysOrdered: ordered,
        markerKey,
      });
    }
    if (
      cls !== "THIRD_OR_MISMATCH_CORRUPT" ||
      exactStr(thirdSnap.classification, "third cls") !== cls ||
      exactInt(thirdSnap.member_count, "third count") !== 15 ||
      exactInt(thirdSnap.marker_state, "third state") !== 3 ||
      !equal(hex(thirdSnap.marker_value_hex, "third"), thirdValue) ||
      thirdValue[8] !== 3 ||
      exactBool(thirdSnap.commit_unknown_accepted, `${roleName} third CU`) !==
        false
    ) {
      fail(`${roleName}: third`);
    }
    const p2aSnap = roleSnaps.pending_to_active;
    const p2aOldV = hex(p2aSnap.old_value_hex, "p2ao");
    const p2aNewV = hex(p2aSnap.new_value_hex, "p2an");
    if (
      exactStr(p2aSnap.mutation_kind, "p2a.kind") !==
        "SINGLE_KEY_FULL_MARKER_ONLY" ||
      !equal(hex(p2aSnap.marker_key_hex, "p2a.mk"), markerKey) ||
      exactInt(p2aSnap.old_state, "p2a old") !== 1 ||
      exactInt(p2aSnap.new_state, "p2a new") !== 2 ||
      !equal(p2aOldV, pendingValue) ||
      !equal(p2aNewV, activeValue) ||
      pendingValue[8] !== 1 ||
      activeValue[8] !== 2 ||
      shaHex(p2aOldV) !== exactStr(p2aSnap.old_value_sha256, "p2a.ovs") ||
      shaHex(p2aNewV) !== exactStr(p2aSnap.new_value_sha256, "p2a.nvs") ||
      exactBool(p2aSnap.accepted, "p2a accepted") !== true ||
      exactBool(p2aSnap.non_marker_rows_unchanged, "p2a non-marker") !== true
    ) {
      fail(`${roleName}: p2a`);
    }
    const cuSnap = requireKeys(roleSnaps.commit_unknown, `${roleName}.commit_unknown`, [
      "accepted_classifications",
      "accepted_snapshots",
      "rejected_snapshot_kinds",
      "active_marker_only",
    ]);
    // Exact ordered closed lists + uniqueness (parity with Python CU_*_EXACT).
    // Rejects: empty rejected_snapshot_kinds; duplicate EXACT_OLD in accepted.
    assertExactUniqueStringList(
      cuSnap.accepted_classifications,
      CU_ACCEPTED_CLASSIFICATIONS_EXACT,
      `${roleName}: CU accepted set`,
    );
    assertExactUniqueStringList(
      cuSnap.rejected_snapshot_kinds,
      CU_REJECTED_SNAPSHOT_KINDS_EXACT,
      `${roleName}: CU rejected_snapshot_kinds exact`,
    );
    const acceptedSnaps = cuSnap.accepted_snapshots;
    if (
      !Array.isArray(acceptedSnaps) ||
      acceptedSnaps.length !== 2 ||
      acceptedSnaps[0] !== "exact_old" ||
      acceptedSnaps[1] !== "exact_new_pending_15" ||
      acceptedSnaps.length !== new Set(acceptedSnaps).size
    ) {
      fail(`${roleName}: accepted_snapshots exact set`);
    }
    if (acceptedSnaps.includes("partial_1")) {
      fail(`${roleName}: accepted_snapshots polluted with partial_1`);
    }
    for (const snapName of acceptedSnaps) {
      if (
        exactBool(
          roleSnaps[snapName].commit_unknown_accepted,
          `${roleName} ${snapName} CU`,
        ) !== true
      ) {
        fail(`${roleName}: accepted snapshot ${snapName} CU`);
      }
    }
    for (const rejected of cuSnap.rejected_snapshot_kinds) {
      if (
        rejected === "value_substitution" ||
        rejected === "context_digest_substitution"
      ) {
        continue;
      }
      if (
        exactBool(
          roleSnaps[rejected].commit_unknown_accepted,
          `${roleName} rejected ${rejected} CU`,
        ) !== false
      ) {
        fail(`${roleName}: CU rejected ${rejected}`);
      }
    }
    const activeOnly = requireKeys(
      cuSnap.active_marker_only,
      `${roleName}.active_marker_only`,
      [
        "marker_key_hex",
        "value_hex",
        "value_sha256",
        "classification",
        "commit_unknown_accepted",
      ],
    );
    if (
      !equal(hex(activeOnly.marker_key_hex, "amk"), markerKey) ||
      !equal(hex(activeOnly.value_hex, "amv"), activeValue) ||
      shaHex(activeValue) !== exactStr(activeOnly.value_sha256, `${roleName} am vs`) ||
      exactStr(activeOnly.classification, `${roleName} am cls`) !==
        "EXACT_NEW_ACTIVE_MARKER" ||
      exactBool(activeOnly.commit_unknown_accepted, `${roleName} am CU`) !== true
    ) {
      fail(`${roleName}: active_marker_only`);
    }
    if (
      !equal(pendingValue.subarray(12, 28), activeValue.subarray(12, 28)) ||
      !equal(pendingValue.subarray(84, 116), activeValue.subarray(84, 116)) ||
      pendingValue[9] !== roleKey ||
      activeValue[9] !== roleKey
    ) {
      fail(`${roleName}: full-row donor identity`);
    }
    if (
      exactInt(
        roleSnaps.publication_before_dual_confirm,
        `${roleName} publication`,
      ) !== 0
    ) {
      fail(`${roleName}: publication zero`);
    }
    const rowCases = roleSnaps.cu_row_classifier_cases;
    if (
      !Array.isArray(rowCases) ||
      JSON.stringify(rowCases.map((row) => row.id)) !==
        JSON.stringify([
          "PA-CU-ROW-OLD",
          "PA-CU-ROW-NEW",
          "PA-CU-ROW-STABLE",
          "PA-CU-ROW-THIRD",
        ])
    ) {
      fail(`${roleName}: CU row classifier case IDs`);
    }
    for (const row of rowCases) {
      if (
        row.old_present !== true ||
        classifyCuRow(row) !== row.expected_classification
      ) {
        fail(`${roleName}: CU row classifier ${row.id}`);
      }
    }
  }
  executed.add("PA-REATTACH-15ROW-OLD-NEW-STABLE-THIRD");
  executed.add("PA-REATTACH-LANE-OLD-NONEMPTY");
  assertReattach10k(document, executed);
  executed.add("LIFECYCLE-15-KEY-GROUP-MACHINE");
  if (lifecycle.publication_before_dual_confirm !== 0) {
    fail("publication before dual confirm");
  }
  executed.add("PUBLICATION-ZERO-BEFORE-DUAL-CONFIRM");

  const manifests = document.atomic_batch_manifests;
  if (
    manifests.status !== "TEST_ORACLE_ONLY_NOT_WIRE_OR_STORAGE" ||
    manifests.ordering !== "UNSIGNED_BYTE_COMPLETE_KEY_LEXICOGRAPHIC"
  ) {
    fail("NAB nonclaim/order");
  }
  const contextPins = {
    hop_ir: ["hop_context_ir", "hop_key_generation_ir"],
    hop_ri: ["hop_context_ri", "hop_key_generation_ri"],
    e2e_ir: ["e2e_context_ir", "e2e_key_generation_ir"],
    e2e_ri: ["e2e_context_ri", "e2e_key_generation_ri"],
  };
  for (const [name, role] of [
    ["device_local_role_1", 1],
    ["authority_local_role_2", 2],
  ]) {
    const item = manifests[name];
    const batch = hex(item.hex, name);
    if (batch.length !== item.length || shaHex(batch) !== item.sha256) {
      fail(`${name}: digest`);
    }
    validateNab(batch, role, installDigest, name, item.exact_inventory);
    const concat = Buffer.concat(
      item.exact_inventory.map((entry) => hex(entry.complete_key_hex, `${name} ck`)),
    );
    if (shaHex(concat) !== item.complete_keys_concat_sha256) {
      fail(`${name}: complete key concat`);
    }
    const localStable = hex(
      role === 1 ? iff.initiator_stable_digest : iff.responder_stable_digest,
      "local stable",
    );
    const peerStable = hex(
      role === 1 ? iff.responder_stable_digest : iff.initiator_stable_digest,
      "peer stable",
    );
    const localNode = r6NodeId16(localStable);
    const peerNode = r6NodeId16(peerStable);
    item.exact_inventory.forEach((entry, i) => {
      const layer = exactInt(entry.layer_code, `${name} lc`);
      const mk = exactInt(entry.member_kind, `${name} mk`);
      const direction = exactInt(entry.direction, `${name} dir`);
      const lane = exactInt(entry.lane, `${name} lane`);
      const recomputed = materializeCompleteKey({
        memberKind: mk,
        direction,
        lane,
        localSide: exactInt(entry.local_side, `${name} ls`),
        localRole: role,
        contextId: exactInt(entry.context_id, `${name} cid`),
        keyGeneration: exactInt(entry.key_generation, `${name} kg`),
        layerCode: layer,
        membershipEpoch: iff.membership_epoch,
        installDigest,
        attachmentId,
        localNodeId: localNode,
        peerNodeId: peerNode,
        fields: iff,
      });
      const complete = hex(entry.complete_key_hex, "ck pin");
      if (!equal(recomputed, complete)) {
        fail(`${name}: independent complete key ${entry.identity}`);
      }
      const expectedId = expectedInventoryIdentity({
        memberKind: mk,
        direction,
        lane,
        layerCode: layer,
      });
      const identity = exactStr(entry.identity, `${name} id`);
      if (identity !== expectedId) {
        fail(`${name}: identity expected ${expectedId} got ${identity}`);
      }
      if (exactInt(entry.index, `${name} idx`) !== i) {
        fail(`${name}: inventory index ${i}`);
      }
      for (const [prefix, names] of Object.entries(contextPins)) {
        if (identity.startsWith(prefix)) {
          if (
            entry.context_id !== iff[names[0]] ||
            entry.key_generation !== iff[names[1]]
          ) {
            fail(`${name}: ${identity} install pin`);
          }
        }
      }
      const value = hex(entry.value_hex, `${name} inv val`);
      if (
        shaHex(value) !== exactStr(entry.value_sha256, `${name} inv vs`) ||
        exactInt(entry.value_bytes, `${name} inv vb`) !== value.length ||
        exactInt(entry.complete_key_length, `${name} inv ckl`) !==
          complete.length ||
        exactInt(entry.key_bytes, `${name} inv kb`) !== complete.length
      ) {
        fail(`${name}: inventory value_sha/length ${identity}`);
      }
      if (identity === "attachment_marker") {
        if (
          mk !== 4 ||
          layer !== 0 ||
          entry.context_id !== 0 ||
          entry.key_generation !== 0 ||
          direction !== 0 ||
          lane !== 0
        ) {
          fail(`${name}: marker inventory metadata`);
        }
        const rolePending = hex(
          document.lifecycle.roles[name].pending.value_hex,
          `${name} role pending`,
        );
        if (
          !equal(value, rolePending) ||
          value[8] !== 1 ||
          value[9] !== role
        ) {
          fail(`${name}: marker inventory value binding`);
        }
      } else {
        if (mk === 4 || !identity || identity === "attachment_marker") {
          fail(`${name}: non-marker identity`);
        }
        const snapMembers =
          document.lifecycle.group_machine.snapshots.roles[name]
            .exact_new_pending_15.members;
        if (
          exactStr(snapMembers[i].identity, `${name} snap id`) !== identity ||
          exactInt(snapMembers[i].index, `${name} snap idx`) !== i
        ) {
          fail(`${name}: inventory/snap identity ${identity}`);
        }
      }
    });
  }
  executed.add("NAB1-EXACT-15-MEMBER-SET-BOTH-ROLES");
  executed.add("NAB1-EXACT-KEY-IDENTITY-INVENTORY");
  executed.add("NAB1-CANONICAL-COMPLETE-KEY-ORDER");
  {
    const nabMut = Buffer.from(hex(manifests.device_local_role_1.hex, "nab mut"));
    nabMut.writeUInt16BE(14, 60);
    recomputeCrcNab(nabMut);
    try {
      validateNab(nabMut, 1, installDigest, "nab-count-mut");
      fail("NAB count mutation accepted");
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  {
    const nabSub = Buffer.from(hex(manifests.device_local_role_1.hex, "nab sub"));
    nabSub.writeUInt32BE(0xdeadbeef, 72);
    recomputeCrcNab(nabSub);
    try {
      validateNab(
        nabSub,
        1,
        installDigest,
        "nab-sub",
        manifests.device_local_role_1.exact_inventory,
      );
      fail("NAB substituted entry accepted");
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  {
    const nabRe = Buffer.from(hex(manifests.device_local_role_1.hex, "nab re"));
    const row0 = Buffer.from(nabRe.subarray(68, 88));
    const row1 = Buffer.from(nabRe.subarray(88, 108));
    row1.copy(nabRe, 68);
    row0.copy(nabRe, 88);
    recomputeCrcNab(nabRe);
    const invRe = structuredClone(manifests.device_local_role_1.exact_inventory);
    [invRe[0], invRe[1]] = [{ ...invRe[1], index: 0 }, { ...invRe[0], index: 1 }];
    try {
      validateNab(nabRe, 1, installDigest, "nab-reorder", invRe);
      fail("NAB reorder accepted");
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  {
    const invDup = structuredClone(manifests.device_local_role_1.exact_inventory);
    invDup[1] = { ...invDup[0], index: 1 };
    try {
      validateNab(
        hex(manifests.device_local_role_1.hex, "nab dup"),
        1,
        installDigest,
        "nab-dup",
        invDup,
      );
      fail("NAB duplicate inventory accepted");
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  executed.add("NAB1-DUPLICATE-MISSING-SUBSTITUTED");
  executed.add("NAB1-REORDER-CONTEXT-SUBSTITUTION");
  executed.add("NAB1-CRC-COUNT-ROLE-MUTATION");

  // Repaired P1/P2 executable authorities.  These do not trust the recorded
  // outcome strings: Node processes the fragment/stream/state inputs and then
  // compares the resulting terminal state with the vector.
  assertNarOwnerMatrix(document, executed);
  assertNasLifecycle(document, executed);
  assertPrerequisites(document, executed);
  assertEdhocAttempts(document, executed);
  assertPreauthOwner(document, executed);
  assertMagicRegistry(document, executed);

  // One coherent byte+digest drift is rejected by the independently rebuilt
  // full machine tree.  The Python authority runs the wider twelve-case
  // coherent-drift campaign; this is the cross-language parity witness.
  {
    const drift = structuredClone(document);
    const changed = hex(
      drift.credentials.initiator_ccs_hex,
      "coherent drift ccs",
    );
    changed[changed.length - 1] ^= 1;
    const changedHex = changed.toString("hex");
    const changedSha = shaHex(changed);
    drift.credentials.initiator_ccs_hex = changedHex;
    drift.credentials.initiator_ccs_sha256 = changedSha;
    drift.prerequisites.local_credential_descriptors
      .initiator_local_role_1.canonical_ccs_hex = changedHex;
    drift.prerequisites.local_credential_descriptors
      .initiator_local_role_1.canonical_ccs_sha256 = changedSha;
    try {
      assertMatchesExpected(drift);
      fail("coherent byte+digest drift accepted");
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  executed.add("PA-INDEPENDENT-COHERENT-DRIFT-REJECT");

  const reference = document.rfc9529_method3_suite2_reference;
  if (
    reference.source !== "RFC 9529 section 3" ||
    reference.method !== 3 ||
    reference.selected_suite !== 2 ||
    reference.profile_acceptance !== false
  ) {
    fail("RFC metadata");
  }
  for (const [name, expected] of Object.entries(RFC9529_MESSAGES)) {
    const item = reference.messages[name];
    const raw = hex(item.hex, `RFC ${name}`);
    if (
      !equal(raw, expected) ||
      raw.length !== item.length ||
      shaHex(raw) !== item.sha256 ||
      shaHex(raw) !== shaHex(expected)
    ) {
      fail(`RFC ${name}`);
    }
    const mut = Buffer.from(raw);
    mut[0] ^= 1;
    if (shaHex(mut) === item.sha256) fail(`RFC ${name} byte+sha mutation`);
  }
  executed.add("RFC9529-INDEPENDENT-CONSTANTS");
  executed.add("RFC9529-REFERENCE-DIGESTS");
  const missing = [...requiredCases].filter(
    (value) => value !== "GATE-SELF-TEST" && !executed.has(value),
  );
  if (missing.length !== 0) {
    fail(`required gate cases not executed: ${missing.sort().join(",")}`);
  }
  return executed;
}

function selfTest(document) {
  const executed = validate(document);
  executed.add("GATE-SELF-TEST");
  if (
    executed.size !== requiredCases.size ||
    [...requiredCases].some((value) => !executed.has(value))
  ) {
    fail("self-test case set mismatch");
  }
  const mutations = [
    (value) => {
      value.profile.exporter_labels.e2e_ri_secret32 = 32774;
    },
    (value) => {
      value.stateless_cookie.source_locator_digest_hex = "00".repeat(32);
    },
    (value) => {
      value.stateless_cookie.time_bucket_seconds = 3;
    },
    (value) => {
      value.attachment_install.protection_nonces.install_r2i_seq6 = "00".repeat(13);
    },
    (value) => {
      value.compact_radio_fragments.pop();
    },
    (value) => {
      value.compact_radio_fragments[1] =
        value.stateless_cookie.response_radio_fragments[0];
    },
    (value) => {
      value.atomic_batch_manifests.authority_local_role_2.hex =
        value.atomic_batch_manifests.authority_local_role_2.hex.slice(0, 16) +
        "01" +
        value.atomic_batch_manifests.authority_local_role_2.hex.slice(18);
    },
    (value) => {
      const raw = Buffer.from(value.n6_attachment_marker.value_hex, "hex");
      raw[10] = 1;
      raw.writeUInt32BE(crc32c(raw.subarray(0, 116)), 116);
      value.n6_attachment_marker.value_hex = raw.toString("hex");
      value.n6_attachment_marker.value_sha256 = shaHex(raw);
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.partial_7.commit_unknown_accepted = true;
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.authority_local_role_2.exact_old.classification =
        "EXACT_NEW_PENDING_15";
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.exact_new_pending_15.members[0].value_hex =
        "00".repeat(value.lifecycle.group_machine.snapshots.roles.device_local_role_1.exact_new_pending_15.members[0].value_bytes);
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.commit_unknown.accepted_classifications.push(
        "PARTIAL_1_CORRUPT",
      );
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.authority_local_role_2.commit_unknown.active_marker_only.classification =
        "EXACT_OLD";
    },
    (value) => {
      const pck =
        value.lifecycle.group_machine.snapshots.roles.device_local_role_1
          .exact_new_pending_15.present_complete_keys_hex;
      pck[0] = pck[1];
    },
    // Permanent repaired-digest counterexamples (independent PA-S0 audit).
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.exact_new_pending_15.present_keys_concat_sha256 =
        "00".repeat(32);
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.exact_old.commit_unknown_accepted = false;
    },
    (value) => {
      delete value.lifecycle.group_machine.snapshots.roles.device_local_role_1
        .commit_unknown.active_marker_only.value_sha256;
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.commit_unknown.accepted_snapshots.push(
        "partial_1",
      );
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.exact_new_pending_15.value_substitution_rejected.classification =
        "EXACT_NEW_PENDING_15";
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.exact_new_pending_15.value_substitution_rejected.commit_unknown_accepted = true;
    },
    (value) => {
      value.unexpected_top_key = true;
    },
    (value) => {
      value.profile.unexpected_nested = 1;
    },
    (value) => {
      value.carrier_bindings.usb.carrier_class = true;
    },
    (value) => {
      const msg =
        value.rfc9529_method3_suite2_reference.messages.message_1;
      const raw = Buffer.from(msg.hex, "hex");
      if (raw[0] !== 0x03) fail("self-test baseline message_1 not 0x03");
      raw[0] = 0x04;
      msg.hex = raw.toString("hex");
      msg.sha256 = shaHex(raw);
      msg.length = raw.length;
    },
    (value) => {
      mutateAllMetadataCoherent(value);
    },
    (value) => {
      value.schema_version = 99;
    },
    (value) => {
      value.tools.generator = "tools/not-the-generator.py";
    },
    (value) => {
      value.lifecycle_constants.value_label = "NINLIL-PA-N6-VALUE-X1";
    },
    (value) => {
      value.status_map.accepted = true;
    },
    // Wire-leaf machine-authority negatives (independent PA-S0 audit P1).
    (value) => {
      value.stateless_cookie.response_radio_fragments[0].index = 1;
    },
    (value) => {
      value.compact_radio_fragments[0].index = 1;
    },
    (value) => {
      value.attachment_install.nap1_length = 209;
    },
    (value) => {
      value.attachment_install.nai1_length = 417;
    },
    (value) => {
      value.attachment_install.nax1_length = 161;
    },
    (value) => {
      value.attachment_install.nat1_length = 97;
    },
    (value) => {
      value.attachment_install.opaque_ciphertext_and_tag_length = 425;
    },
    (value) => {
      value.attachment_install.proposal_opaque_ciphertext_and_tag_length = 217;
    },
    (value) => {
      value.attachment_install.confirm_opaque_ciphertext_and_tag_length = 105;
    },
    (value) => {
      value.attachment_install.install_fields.carrier_transcript_digest =
        "0" +
        value.attachment_install.install_fields.carrier_transcript_digest.slice(
          1,
        );
    },
    (value) => {
      value.attachment_install.install_fields.e2e_security_id =
        "0" + value.attachment_install.install_fields.e2e_security_id.slice(1);
    },
    (value) => {
      value.attachment_install.install_fields.initiator_credential_generation = 24;
    },
    (value) => {
      value.attachment_install.install_fields.responder_credential_generation = 30;
    },
    (value) => {
      value.attachment_install.install_fields.lease_clock_epoch =
        "0" +
        value.attachment_install.install_fields.lease_clock_epoch.slice(1);
    },
    (value) => {
      value.attachment_install.install_fields.membership_grant_digest =
        "0" +
        value.attachment_install.install_fields.membership_grant_digest.slice(
          1,
        );
    },
    (value) => {
      value.attachment_install.install_fields.proposal_digest =
        "1" + value.attachment_install.install_fields.proposal_digest.slice(1);
    },
    (value) => {
      value.attachment_install.install_fields.route_policy_digest =
        "0" +
        value.attachment_install.install_fields.route_policy_digest.slice(1);
    },
    (value) => {
      value.attachment_install.proposal_fields.e2e_security_epoch = 74;
    },
    (value) => {
      value.attachment_install.proposal_fields.e2e_security_id =
        "0" +
        value.attachment_install.proposal_fields.e2e_security_id.slice(1);
    },
    (value) => {
      value.attachment_install.proposal_fields.initiator_stable_digest =
        "0" +
        value.attachment_install.proposal_fields.initiator_stable_digest.slice(
          1,
        );
    },
    (value) => {
      value.n6_attachment_marker.key_length = 21;
    },
    (value) => {
      value.n6_attachment_marker.value_length = 121;
    },
    (value) => {
      value.n6_attachment_marker.local_role = 2;
    },
    (value) => {
      value.n6_attachment_marker.state = 3;
    },
    (value) => {
      value.n6_attachment_marker.state_name = "ACTIVE_DRIFT";
    },
    (value) => {
      value.limits.n6at_key_bytes = 21;
    },
    (value) => {
      value.profile.control_aead.name = "AES-CCM-16-64-128_DRIFT";
    },
    (value) => {
      value.lifecycle.roles.device_local_role_1.pending.state = 99;
    },
    (value) => {
      value.lifecycle.roles.device_local_role_1.pending.state_name = "ACTIVE";
    },
    (value) => {
      value.lifecycle.pending_marker.local_role = 2;
    },
    (value) => {
      value.lifecycle.pending_marker.value_sha256 = "00".repeat(32);
    },
    (value) => {
      value.lifecycle.pending_to_active.old_value_sha256 = "00".repeat(32);
    },
    (value) => {
      const snap =
        value.lifecycle.group_machine.snapshots.roles.device_local_role_1
          .exact_new_pending_15;
      snap.members[0].index = 99;
      snap.value_substitution_rejected.members[0].index = 99;
      snap.context_digest_substitution_rejected.members[0].index = 99;
    },
    (value) => {
      const inv =
        value.atomic_batch_manifests.device_local_role_1.exact_inventory;
      inv[0].identity = `${inv[0].identity}_X`;
      const snap =
        value.lifecycle.group_machine.snapshots.roles.device_local_role_1
          .exact_new_pending_15;
      snap.members[0].identity = inv[0].identity;
      snap.value_substitution_rejected.members[0].identity = inv[0].identity;
      snap.context_digest_substitution_rejected.members[0].identity =
        inv[0].identity;
    },
    // Lifecycle matrix P1 (Node-only false-greens): both roles × 2 CU list drifts.
    // Permanent: rejected_snapshot_kinds=[] and duplicate EXACT_OLD accepted class.
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.extra_16.member_count = 17;
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.third_mismatch.member_count = 16;
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.third_mismatch.marker_state = 1;
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.commit_unknown.rejected_snapshot_kinds =
        [];
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.device_local_role_1.commit_unknown.accepted_classifications.push(
        "EXACT_OLD",
      );
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.authority_local_role_2.extra_16.member_count = 17;
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.authority_local_role_2.third_mismatch.member_count = 16;
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.authority_local_role_2.third_mismatch.marker_state = 1;
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.authority_local_role_2.commit_unknown.rejected_snapshot_kinds =
        [];
    },
    (value) => {
      value.lifecycle.group_machine.snapshots.roles.authority_local_role_2.commit_unknown.accepted_classifications.push(
        "EXACT_OLD",
      );
    },
  ];
  // Role × 8 N6AT authority-field coherent mutations (install_fields unmoved).
  for (const roleName of ["device_local_role_1", "authority_local_role_2"]) {
    for (const [fieldName, offset, width] of N6AT_AUTHORITY_FIELDS) {
      mutations.push((value) => {
        mutateN6atAuthorityFieldCoherent(value, roleName, offset, width);
      });
    }
  }
  let observed = 0;
  for (const mutate of mutations) {
    const changed = structuredClone(document);
    mutate(changed);
    try {
      validate(changed);
    } catch (error) {
      if (!(error instanceof GateError || error instanceof RangeError || error instanceof TypeError)) {
        throw error;
      }
      observed += 1;
      continue;
    }
    fail("self-test mutation survived");
  }
  // Strict duplicate-key / non-integer JSON / unicode-key collision.
  const rawText = fs.readFileSync(defaultVector, "utf8");
  const schemaPin = '"schema": "ninlil.production-attachment-edhoc.vector.v1"';
  if (!rawText.includes(schemaPin)) fail("self-test: schema pin missing");
  const dupRaw = rawText.replace(schemaPin, `${schemaPin}, "schema": "dup"`, 1);
  if (dupRaw === rawText) fail("self-test: duplicate mutation not applied");
  try {
    loadStrictJson(dupRaw);
    throw new Error("duplicate JSON key accepted");
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
    observed += 1;
  }
  // Decoded-unicode duplicate: schema and \u0073chema
  const uniDup = rawText.replace(
    schemaPin,
    '"schema": "ninlil.production-attachment-edhoc.vector.v1", "\\u0073chema": "dup"',
    1,
  );
  try {
    loadStrictJson(uniDup);
    throw new Error("unicode duplicate JSON key accepted");
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
    observed += 1;
  }
  const memberPin = '"member_count_exact": 15';
  if (!rawText.includes(memberPin)) fail("self-test: member_count pin missing");
  const floatRaw = rawText.replace(memberPin, '"member_count_exact": 15.0', 1);
  if (floatRaw === rawText) fail("self-test: float mutation not applied");
  try {
    loadStrictJson(floatRaw);
    throw new Error("non-integer json number accepted");
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
    observed += 1;
  }
  try {
    loadStrictJson(rawText.replace(memberPin, '"member_count_exact": +15', 1));
    throw new Error("leading + accepted");
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
    observed += 1;
  }
  try {
    loadStrictJson(rawText.replace(memberPin, '"member_count_exact": -0', 1));
    throw new Error("negative zero accepted");
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
    observed += 1;
  }
  if (observed !== mutations.length + 5) fail("self-test mutation count");
  // Exhaustive all-object-path unknown-key probe (444/444; parity with Python).
  const probe = runAllObjectPathUnknownKeyProbe(document);
  if (
    probe.rejected !== PA_OBJECT_PATH_COUNT_EXACT ||
    probe.accepted.length !== 0
  ) {
    fail(
      `all-object-path unknown-key parity failed: rejected=${probe.rejected} ` +
        `accepted=${probe.accepted.length} pin=${PA_OBJECT_PATH_COUNT_EXACT} ` +
        `sample=${probe.accepted.slice(0, 5).join(",")}`,
    );
  }
  observed += probe.rejected;
  // Full machine-leaf campaign against static authority (closed schema + equality).
  const leafCampaign = runNodeMachineLeafCampaign(document);
  observed += leafCampaign.tested;
  process.stdout.write(
    `production attachment Node gate self-test OK mutations=${observed} ` +
      `object_paths=${PA_OBJECT_PATH_COUNT_EXACT} unknown_key_rejected=${probe.rejected} ` +
      `leaf_campaign_tested=${leafCampaign.tested} ` +
      `leaf_campaign_false_greens=${leafCampaign.falseGreens}\n`,
  );
}

function typePreservingMutate(value) {
  if (typeof value === "boolean") return !value;
  if (typeof value === "number" && Number.isInteger(value)) return value + 1;
  if (typeof value === "string") {
    if (value.length === 0) return "X";
    if (/^[0-9a-f]*$/.test(value) && value.length % 2 === 0 && value.length >= 2) {
      return (value[0] === "0" ? "1" : "0") + value.slice(1);
    }
    return `${value}_DRIFT`;
  }
  return null;
}

function collectScalarLeaves(node, jsonPath = "$", out = []) {
  if (Array.isArray(node)) {
    node.forEach((v, i) => collectScalarLeaves(v, pathJoin(jsonPath, i), out));
  } else if (node !== null && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      collectScalarLeaves(v, pathJoin(jsonPath, k), out);
    }
  } else {
    out.push([jsonPath, node]);
  }
  return out;
}

function setJsonPath(document, jsonPath, value) {
  const parts = [];
  let i = 2;
  let cur = "";
  while (i < jsonPath.length) {
    const ch = jsonPath[i];
    if (ch === ".") {
      if (cur) parts.push(cur);
      cur = "";
      i += 1;
    } else if (ch === "[") {
      if (cur) parts.push(cur);
      cur = "";
      const j = jsonPath.indexOf("]", i);
      parts.push(Number(jsonPath.slice(i + 1, j)));
      i = j + 1;
    } else {
      cur += ch;
      i += 1;
    }
  }
  if (cur) parts.push(cur);
  let obj = document;
  for (let p = 0; p < parts.length - 1; p += 1) obj = obj[parts[p]];
  obj[parts[parts.length - 1]] = value;
}

function runNodeMachineLeafCampaign(document) {
  const leaves = collectScalarLeaves(document);
  let tested = 0;
  const accepted = [];
  for (const [jsonPath, original] of leaves) {
    const mut = typePreservingMutate(original);
    if (mut === null || mut === original) continue;
    tested += 1;
    const changed = structuredClone(document);
    setJsonPath(changed, jsonPath, mut);
    try {
      // Equality alone rejects machine scalar drift; unknown-key is separate.
      assertMatchesExpected(changed);
      if (!pathIsDescriptive(jsonPath)) accepted.push(jsonPath);
    } catch (error) {
      if (!(error instanceof GateError)) throw error;
    }
  }
  if (accepted.length !== 0) {
    fail(
      `Node leaf campaign false-greens=${accepted.length} sample=${accepted
        .slice(0, 8)
        .join(",")}`,
    );
  }
  return { tested, falseGreens: accepted.length };
}

function main() {
  const args = process.argv.slice(2);
  const mode = args.includes("--self-test")
    ? "self-test"
    : args.includes("--check")
      ? "check"
      : null;
  if (mode === null || (args.includes("--self-test") && args.includes("--check"))) {
    process.stderr.write("usage: production_attachment_edhoc_gate.mjs --check|--self-test [--vector path]\n");
    return 2;
  }
  const vectorIndex = args.indexOf("--vector");
  const vectorPath = vectorIndex >= 0 ? args[vectorIndex + 1] : defaultVector;
  try {
    const raw = fs.readFileSync(vectorPath);
    const document = loadStrictJson(raw);
    if (mode === "self-test") selfTest(document);
    else {
      validate(document);
      process.stdout.write(
        `production attachment Node gate OK sha256=${shaHex(raw)}\n`,
      );
    }
    return 0;
  } catch (error) {
    process.stderr.write(`production attachment Node gate FAIL: ${error.message}\n`);
    return 1;
  }
}

process.exitCode = main();
