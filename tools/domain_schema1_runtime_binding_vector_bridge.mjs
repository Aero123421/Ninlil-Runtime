#!/usr/bin/env node
// Independent Node bridge for Domain schema1 T1a digests + full RO transcript.
// Does not import the Python generator, Python bridge, or production C.
// Literal KAT digests and transcript fields; coherent digest mutants reject.

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

const FORMAT = "ninlil-domain-store-schema1-runtime-binding-v1";
const EXPECTED_STATUS = "PROPOSED_DOCS_ONLY";

// Hard-coded normative T1a COMMIT_UNKNOWN RO scan transcript (all cases).
const T1A_TRANSCRIPT_KAT = Object.freeze({
  transaction_mode: "READ_ONLY",
  storage_read_only_begin: 1,
  iterator_open: 1,
  iterator_exhausted: 1,
  iterator_close: 1,
  rollback: 1,
  storage_read_write_begin: 0,
  storage_put: 0,
  storage_erase: 0,
  storage_commit: 0,
  bearer_open: 0,
  callback: 0,
  public_handle: 0,
  publish: 0,
});

const T1A_CLASS_MAP = Object.freeze({
  T1A_COMMIT_UNKNOWN_ALL_OLD_0_OF_17: ["OLD", 0],
  T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17: ["NEW", 17],
  T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17: ["NINLIL_E_STORAGE_CORRUPT", 1],
  T1A_COMMIT_UNKNOWN_PARTIAL_16_OF_17: ["NINLIL_E_STORAGE_CORRUPT", 16],
  T1A_COMMIT_UNKNOWN_EXTRA_ROW: ["NINLIL_E_STORAGE_CORRUPT", 18],
  T1A_COMMIT_UNKNOWN_FORMAT_MISMATCH: ["NINLIL_E_STORAGE_CORRUPT", 17],
});

function fail(message) {
  throw new Error(message);
}

function u16(value) {
  const buf = Buffer.alloc(2);
  buf.writeUInt16BE(value & 0xffff, 0);
  return buf;
}

function u32(value) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(value >>> 0, 0);
  return buf;
}

function independentSnapshotSha256(rows) {
  const ordered = [...rows].sort((a, b) => Buffer.compare(a[0], b[0]));
  const parts = [Buffer.from("NINLIL-DOMAIN-INIT-SNAPSHOT-V1"), u32(ordered.length)];
  for (const [key, value] of ordered) {
    parts.push(u16(key.length), key, u32(value.length), value);
  }
  return crypto.createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

// Deterministic canonical JSON (sort keys, no spaces) matching Python gate.
function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function canonicalWithoutIntegrityBytes(document) {
  const body = {};
  for (const key of Object.keys(document).sort()) {
    if (key === "integrity") continue;
    body[key] = document[key];
  }
  // Rebuild sorted recursively.
  return Buffer.from(canonicalJson(body), "utf8");
}

function refreshIntegrity(document) {
  document.integrity = {
    scope: "canonical JSON of this document with integrity omitted",
    sha256: crypto
      .createHash("sha256")
      .update(canonicalWithoutIntegrityBytes(document))
      .digest("hex"),
  };
}

function validate(document) {
  if (document.format !== FORMAT) fail("format");
  if (document.status !== EXPECTED_STATUS) {
    fail(`status ${document.status}`);
  }
  const expectedDigest = crypto
    .createHash("sha256")
    .update(canonicalWithoutIntegrityBytes(document))
    .digest("hex");
  if (document.integrity?.sha256 !== expectedDigest) {
    fail("document integrity digest mismatch");
  }

  const t1a = document.initialization_transition_byte_kats?.T1a;
  if (!Array.isArray(t1a) || t1a.length !== Object.keys(T1A_CLASS_MAP).length) {
    fail("T1a case count");
  }
  const seen = new Set();
  for (const caseRow of t1a) {
    const expected = T1A_CLASS_MAP[caseRow.id];
    if (!expected) fail(`unexpected T1a id ${caseRow.id}`);
    if (seen.has(caseRow.id)) fail(`duplicate ${caseRow.id}`);
    seen.add(caseRow.id);
    const [klass, count] = expected;
    if (caseRow.expected_classification !== klass) {
      fail(`${caseRow.id} class`);
    }
    if (caseRow.computed_classification !== klass) {
      fail(`${caseRow.id} computed class`);
    }
    if (caseRow.snapshot_record_count !== count) {
      fail(`${caseRow.id} count`);
    }
    const tr = caseRow.transcript;
    const keys = new Set(Object.keys(tr));
    for (const field of Object.keys(T1A_TRANSCRIPT_KAT)) {
      if (!keys.has(field)) fail(`${caseRow.id} missing transcript.${field}`);
      if (tr[field] !== T1A_TRANSCRIPT_KAT[field]) {
        fail(`${caseRow.id} transcript.${field}`);
      }
    }
    if (keys.size !== Object.keys(T1A_TRANSCRIPT_KAT).length) {
      fail(`${caseRow.id} transcript extra keys`);
    }
    const caseRows = (caseRow.snapshot_records_unsigned_key_order || []).map(
      (row) => [Buffer.from(row.key_hex, "hex"), Buffer.from(row.value_hex, "hex")],
    );
    // Unconditional for all 6 T1a IDs (EXTRA_ROW / FORMAT_MISMATCH included):
    // materialised length must equal declared snapshot_record_count.
    if (caseRows.length !== caseRow.snapshot_record_count) {
      fail(
        `${caseRow.id} materialised=${caseRows.length} != declared=${caseRow.snapshot_record_count}`,
      );
    }
    if (caseRows.length !== count) {
      fail(`${caseRow.id} materialised != class_map count`);
    }
    const recomputed = independentSnapshotSha256(caseRows);
    if (caseRow.snapshot_sha256 !== recomputed) {
      fail(`${caseRow.id} snapshot_sha256 independent mismatch`);
    }
  }
  if (seen.size !== Object.keys(T1A_CLASS_MAP).length) {
    fail("T1a id set incomplete");
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function mutationMustFail(document, label, mutate) {
  const candidate = clone(document);
  mutate(candidate);
  refreshIntegrity(candidate);
  try {
    validate(candidate);
  } catch {
    return;
  }
  fail(`self-test mutation escaped: ${label}`);
}

function selfTest(document) {
  validate(document);
  const t1a = document.initialization_transition_byte_kats.T1a;

  mutationMustFail(document, "status", (d) => {
    d.status = "SPEC_ACCEPTED";
  });
  mutationMustFail(document, "class", (d) => {
    d.initialization_transition_byte_kats.T1a[0].expected_classification =
      "NEW";
  });
  mutationMustFail(document, "transcript_publish", (d) => {
    d.initialization_transition_byte_kats.T1a[0].transcript.publish = 1;
  });
  mutationMustFail(document, "transcript_ro", (d) => {
    d.initialization_transition_byte_kats.T1a[0].transcript.storage_read_only_begin = 0;
  });
  mutationMustFail(document, "transcript_mode", (d) => {
    d.initialization_transition_byte_kats.T1a[0].transcript.transaction_mode =
      "READ_WRITE";
  });
  mutationMustFail(document, "transcript_iterator", (d) => {
    d.initialization_transition_byte_kats.T1a[1].transcript.iterator_close = 0;
  });
  mutationMustFail(document, "transcript_rollback", (d) => {
    d.initialization_transition_byte_kats.T1a[2].transcript.rollback = 0;
  });
  mutationMustFail(document, "transcript_commit", (d) => {
    d.initialization_transition_byte_kats.T1a[3].transcript.storage_commit = 1;
  });
  mutationMustFail(document, "digest_coherent", (d) => {
    const row = d.initialization_transition_byte_kats.T1a.find(
      (c) => c.id === "T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17",
    );
    row.snapshot_sha256 = "a".repeat(64);
  });
  mutationMustFail(document, "digest_coherent_partial", (d) => {
    const row = d.initialization_transition_byte_kats.T1a.find(
      (c) => c.id === "T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17",
    );
    row.snapshot_sha256 = "b".repeat(64);
  });
  // P1: EXTRA declared=18 / materialise 17 + repaired digest must reject.
  mutationMustFail(document, "extra_row_undercount_repaired_digest", (d) => {
    const row = d.initialization_transition_byte_kats.T1a.find(
      (c) => c.id === "T1A_COMMIT_UNKNOWN_EXTRA_ROW",
    );
    if (row.snapshot_record_count !== 18) fail("extra fixture count");
    row.snapshot_records_unsigned_key_order =
      row.snapshot_records_unsigned_key_order.slice(0, 17);
    const caseRows = row.snapshot_records_unsigned_key_order.map((r) => [
      Buffer.from(r.key_hex, "hex"),
      Buffer.from(r.value_hex, "hex"),
    ]);
    row.snapshot_sha256 = independentSnapshotSha256(caseRows);
  });
  // P1: FORMAT declared=17 / materialise 16 + repaired digest must reject.
  mutationMustFail(
    document,
    "format_mismatch_undercount_repaired_digest",
    (d) => {
      const row = d.initialization_transition_byte_kats.T1a.find(
        (c) => c.id === "T1A_COMMIT_UNKNOWN_FORMAT_MISMATCH",
      );
      if (row.snapshot_record_count !== 17) fail("format fixture count");
      row.snapshot_records_unsigned_key_order =
        row.snapshot_records_unsigned_key_order.slice(0, 16);
      const caseRows = row.snapshot_records_unsigned_key_order.map((r) => [
        Buffer.from(r.key_hex, "hex"),
        Buffer.from(r.value_hex, "hex"),
      ]);
      row.snapshot_sha256 = independentSnapshotSha256(caseRows);
    },
  );
  mutationMustFail(document, "digest_donor_old_into_new", (d) => {
    const byId = Object.fromEntries(
      d.initialization_transition_byte_kats.T1a.map((c) => [c.id, c]),
    );
    byId.T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17.snapshot_sha256 =
      byId.T1A_COMMIT_UNKNOWN_ALL_OLD_0_OF_17.snapshot_sha256;
  });
  mutationMustFail(document, "digest_donor_new_into_partial", (d) => {
    const byId = Object.fromEntries(
      d.initialization_transition_byte_kats.T1a.map((c) => [c.id, c]),
    );
    byId.T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17.snapshot_sha256 =
      byId.T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17.snapshot_sha256;
  });

  const dirty = {
    publish: 1,
    storage_read_only_begin: 0,
    rollback: 0,
    iterator_open: 0,
    storage_commit: 1,
    storage_read_write_begin: 1,
    transaction_mode: "READ_WRITE",
  };
  for (let i = 0; i < t1a.length; i += 1) {
    for (const [field, bad] of Object.entries(dirty)) {
      mutationMustFail(document, `transcript_dirty_${field}_on_${t1a[i].id}`, (d) => {
        d.initialization_transition_byte_kats.T1a[i].transcript[field] = bad;
      });
    }
  }

  validate(document);
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 1 || !["--check", "--self-test"].includes(args[0])) {
    fail(
      "usage: domain_schema1_runtime_binding_vector_bridge.mjs --check|--self-test [vector]",
    );
  }
  const vectorPath = args[1] ?? defaultVector;
  const document = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
  if (args[0] === "--self-test") {
    selfTest(document);
    process.stdout.write(
      "domain_schema1_runtime_binding Node bridge self-test OK (digest+transcript mutants rejected)\n",
    );
  } else {
    validate(document);
    process.stdout.write(
      "domain_schema1_runtime_binding Node bridge OK t1a digests+transcript\n",
    );
  }
}

try {
  main();
} catch (error) {
  process.stderr.write(
    `domain_schema1_runtime_binding Node bridge FAIL: ${error.message}\n`,
  );
  process.exitCode = 1;
}
