#!/usr/bin/env node
// Independent Node.js oracle for ADR-0022 closed status raw KATs.
// It does not import the Python generator, the Python gate, or production code.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const defaultVector = path.join(
  here,
  "..",
  "spec",
  "vectors",
  "domain-store-schema1-runtime-binding-v1.json",
);

const expectedCases = new Map([
  ["S4_BINDING_CURRENT_POSITIVE", ["NLR1_BINDING", "CURRENT", "NINLIL_OK"]],
  [
    "S4_BINDING_FORMAT3_FUTURE",
    ["NLR1_BINDING", "FRAMING_VALID_FUTURE", "NINLIL_E_UNSUPPORTED"],
  ],
  [
    "S4_NLR1_RECORD_VERSION2_FUTURE",
    ["NLR1_BINDING", "FRAMING_VALID_FUTURE", "NINLIL_E_UNSUPPORTED"],
  ],
  [
    "S4_NLR1_BINDING_CRC_MISMATCH",
    ["NLR1_BINDING", "MALFORMED_CURRENT", "NINLIL_E_STORAGE_CORRUPT"],
  ],
  [
    "S4_NLR1_BINDING_SHORT",
    ["NLR1_BINDING", "MALFORMED_CURRENT", "NINLIL_E_STORAGE_CORRUPT"],
  ],
  ["S4_NTS3_CURRENT_POSITIVE", ["NTS3", "CURRENT", "NINLIL_OK"]],
  [
    "S4_NTS3_SCHEMA2_FUTURE",
    ["NTS3", "FRAMING_VALID_FUTURE", "NINLIL_E_UNSUPPORTED"],
  ],
  [
    "S4_NTS3_CRC_MISMATCH",
    ["NTS3", "MALFORMED_CURRENT", "NINLIL_E_STORAGE_CORRUPT"],
  ],
  [
    "S4_NTS3_SHORT",
    ["NTS3", "MALFORMED_CURRENT", "NINLIL_E_STORAGE_CORRUPT"],
  ],
  ["S4_M4T_CURRENT_POSITIVE", ["M4T", "CURRENT", "NINLIL_OK"]],
  [
    "S4_M4T_VERSION2_FUTURE",
    ["M4T", "FRAMING_VALID_FUTURE", "NINLIL_E_UNSUPPORTED"],
  ],
  [
    "S4_M4T_CRC_MISMATCH",
    ["M4T", "MALFORMED_CURRENT", "NINLIL_E_STORAGE_CORRUPT"],
  ],
  [
    "S4_M4T_SHORT",
    ["M4T", "MALFORMED_CURRENT", "NINLIL_E_STORAGE_CORRUPT"],
  ],
]);

function fail(message) {
  throw new Error(message);
}

function u16(buffer, offset) {
  return buffer.readUInt16BE(offset);
}

function u32(buffer, offset) {
  return buffer.readUInt32BE(offset);
}

function crc32c(buffer) {
  let crc = 0xffffffff;
  for (const octet of buffer) {
    crc = (crc ^ octet) >>> 0;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = ((crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0)) >>> 0;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function classifyNlr1Binding(key, value) {
  if (key.toString("hex") !== "4e494e4c494c000101") {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (value.length < 16 || value.subarray(0, 4).toString() !== "NLR1") {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (u16(value, 4) !== 1) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  const payloadLength = u32(value, 8);
  if (value.length !== 12 + payloadLength + 4) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (u32(value, value.length - 4) !== crc32c(value.subarray(0, -4))) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  const recordVersion = u16(value, 6);
  if (recordVersion > 1) {
    return "NINLIL_E_UNSUPPORTED";
  }
  if (recordVersion !== 1 || payloadLength < 4) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  return [1, 2].includes(u32(value, 12))
    ? "NINLIL_OK"
    : "NINLIL_E_UNSUPPORTED";
}

const nts3Prefixes = new Set(["TX", "CN", "DS", "EV", "OC", "ES", "RT", "AP"]);

function classifyNts3(key, value) {
  if (
    key.length !== 18
    || !nts3Prefixes.has(key.subarray(0, 2).toString())
    || key.subarray(2).every((octet) => octet === 0)
  ) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (value.length < 20 || value.subarray(0, 4).toString() !== "NTS3") {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  const bodyLength = u32(value, 8);
  if (value.length !== 16 + bodyLength + 4) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (u32(value, value.length - 4) !== crc32c(value.subarray(0, -4))) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (!value.subarray(32, 48).equals(key.subarray(2))) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  const schema = u16(value, 4);
  if (schema > 1) {
    return "NINLIL_E_UNSUPPORTED";
  }
  if (schema !== 1) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (
    u16(value, 6) !== 0
    || value.subarray(12, 16).some((octet) => octet !== 0)
    || bodyLength < 32
  ) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  return "NINLIL_OK";
}

function classifyM4t(key, value) {
  if (key.length !== 16 || key.subarray(0, 3).toString() !== "M4T") {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (value.length !== 72) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (u32(value, 68) !== crc32c(value.subarray(0, 68))) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (
    !key.subarray(3, 7).equals(value.subarray(4, 8))
    || !key.subarray(7, 16).equals(value.subarray(36, 45))
  ) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  if (value[0] > 1) {
    return "NINLIL_E_UNSUPPORTED";
  }
  if (value[0] !== 1) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  const nonzero = (buffer) => buffer.some((octet) => octet !== 0);
  if (
    ![1, 2].includes(value[1])
    || nonzero(value.subarray(2, 4))
    || !nonzero(value.subarray(8, 16))
    || !nonzero(value.subarray(16, 24))
    || !nonzero(value.subarray(24, 28))
    || !nonzero(value.subarray(28, 36))
    || !nonzero(value.subarray(36, 68))
  ) {
    return "NINLIL_E_STORAGE_CORRUPT";
  }
  return "NINLIL_OK";
}

function classify(parser, key, value) {
  if (parser === "NLR1_BINDING") return classifyNlr1Binding(key, value);
  if (parser === "NTS3") return classifyNts3(key, value);
  if (parser === "M4T") return classifyM4t(key, value);
  fail(`unknown parser ${parser}`);
}

function validate(document) {
  const collection = document.closed_status_oracle_vectors;
  if (!collection || !Array.isArray(collection.vectors)) {
    fail("closed status collection missing");
  }
  const byId = new Map(collection.vectors.map((row) => [row.id, row]));
  if (byId.size !== collection.vectors.length || byId.size !== expectedCases.size) {
    fail("closed status vector set is not exact");
  }
  for (const id of byId.keys()) {
    if (!expectedCases.has(id)) fail(`unexpected vector ${id}`);
  }
  const counts = {
    CURRENT: 0,
    FRAMING_VALID_FUTURE: 0,
    MALFORMED_CURRENT: 0,
  };
  for (const [id, [parser, category, status]] of expectedCases) {
    const row = byId.get(id);
    if (!row) fail(`missing vector ${id}`);
    if (
      row.parser !== parser
      || row.category !== category
      || row.expected_status !== status
      || row.canonical_publish !== false
    ) {
      fail(`${id}: metadata mismatch`);
    }
    const key = Buffer.from(row.key_hex, "hex");
    const value = Buffer.from(row.value_hex, "hex");
    if (
      key.toString("hex") !== row.key_hex
      || value.toString("hex") !== row.value_hex
    ) {
      fail(`${id}: invalid canonical hex`);
    }
    const digest = crypto.createHash("sha256").update(value).digest("hex");
    if (digest !== row.value_sha256) fail(`${id}: digest mismatch`);
    const computed = classify(parser, key, value);
    if (computed !== status) {
      fail(`${id}: raw classification ${computed}, want ${status}`);
    }
    counts[category] += 1;
  }
  if (
    collection.fixture_count !== 13
    || collection.current_positive_count !== 3
    || collection.framing_valid_future_count !== 4
    || collection.malformed_current_count !== 6
    || counts.CURRENT !== 3
    || counts.FRAMING_VALID_FUTURE !== 4
    || counts.MALFORMED_CURRENT !== 6
  ) {
    fail("closed status counts mismatch");
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function mutationMustFail(document, label, mutate) {
  const candidate = clone(document);
  mutate(candidate);
  try {
    validate(candidate);
  } catch {
    return;
  }
  fail(`self-test mutation escaped: ${label}`);
}

function vector(document, id) {
  return document.closed_status_oracle_vectors.vectors.find((row) => row.id === id);
}

function selfTest(document) {
  validate(document);
  mutationMustFail(document, "future CRC", (candidate) => {
    const row = vector(candidate, "S4_NTS3_SCHEMA2_FUTURE");
    const raw = Buffer.from(row.value_hex, "hex");
    raw[raw.length - 1] ^= 1;
    row.value_hex = raw.toString("hex");
    row.value_sha256 = crypto.createHash("sha256").update(raw).digest("hex");
  });
  for (const [label, id] of [
    ["NTS3 future key/body binding", "S4_NTS3_SCHEMA2_FUTURE"],
    ["M4T future key/body binding", "S4_M4T_VERSION2_FUTURE"],
  ]) {
    mutationMustFail(document, label, (candidate) => {
      const row = vector(candidate, id);
      const raw = Buffer.from(row.key_hex, "hex");
      raw[raw.length - 1] ^= 1;
      row.key_hex = raw.toString("hex");
    });
  }
  mutationMustFail(document, "future status", (candidate) => {
    vector(candidate, "S4_M4T_VERSION2_FUTURE").expected_status =
      "NINLIL_E_STORAGE_CORRUPT";
  });
  mutationMustFail(document, "missing raw vector", (candidate) => {
    candidate.closed_status_oracle_vectors.vectors.pop();
  });
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 1 || !["--check", "--self-test"].includes(args[0])) {
    fail("usage: domain_store_schema1_binding_gate.mjs --check|--self-test [vector]");
  }
  const vectorPath = args[1] ?? defaultVector;
  const document = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
  if (args[0] === "--self-test") {
    selfTest(document);
    process.stdout.write(
      "domain-store schema1 Node status gate self-test: PASS (5 mutations rejected)\n",
    );
  } else {
    validate(document);
    process.stdout.write(
      "domain-store schema1 Node status gate: PASS (closed-status=13)\n",
    );
  }
}

try {
  main();
} catch (error) {
  process.stderr.write(`domain-store schema1 Node status gate: FAIL: ${error.message}\n`);
  process.exitCode = 1;
}
