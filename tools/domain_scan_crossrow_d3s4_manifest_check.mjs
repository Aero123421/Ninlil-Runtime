#!/usr/bin/env node
/*
 * Independent Node.js verifier for the D3-S4 manifest/shard authority.
 *
 * This program does not invoke Python and does not import the generator.  It
 * pins the pre-sharding 468-vector semantics literally, validates every shard
 * raw hash and canonical byte image, and recomputes the expanded content,
 * order, negative-case, and canonical-document digests one shard at a time.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const MANIFEST_FORMAT = "ninlil-domain-scan-crossrow-manifest-v1";
const SHARD_FORMAT = "ninlil-domain-scan-crossrow-shard-v1";
const EXPANDED_FORMAT = "ninlil-domain-scan-crossrow-v1-d3s4";
const MAX_SHARD_BYTES = 10 * 1024 * 1024;
const FIXED = Object.freeze({
  expanded_vector_count: 468,
  expanded_content_sha256:
    "b18f717e2752c9d617d575c86194ef644f301706263674f2666a5d29ed951e25",
  expanded_order_sha256:
    "17ec848715537a261f274a392d23c586045b87bc0adf1fe65cb1e15c7f0c8c4d",
  expanded_negative_count: 191,
  expanded_negative_sha256:
    "74e0ded28a87d77f002db181a496a70efd29f601833c08d2379e717fff7f00ee",
  expanded_canonical_sha256:
    "33d936597ce617952043f6a0324ba616b8d71acf41cc8744d1b3f771abd54f15",
});
const MANIFEST_KEYS = new Set([
  "format",
  "version",
  "expanded_format",
  "expanded_vector_count",
  "expanded_content_sha256",
  "expanded_order_sha256",
  "expanded_negative_count",
  "expanded_negative_sha256",
  "expanded_canonical_sha256",
  "expanded_key_order",
  "max_shard_bytes",
  "top_level",
  "shards",
]);
const SHARD_KEYS = new Set(["format", "version", "start", "count", "vectors"]);
const ENTRY_KEYS = new Set([
  "path",
  "stage",
  "slice",
  "start",
  "count",
  "bytes",
  "sha256",
  "first_id",
  "last_id",
]);

class CheckError extends Error {}

function fail(message) {
  throw new CheckError(message);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

function pythonAsciiJson(value) {
  // Python json.dumps defaults to ensure_ascii=True.  Replace Unicode in the
  // already-valid stable JSON image; JSON syntax itself is ASCII.
  return stableStringify(value).replace(/[^\x00-\x7f]/gu, (character) => {
    const codepoint = character.codePointAt(0);
    if (codepoint <= 0xffff) {
      return `\\u${codepoint.toString(16).padStart(4, "0")}`;
    }
    const scalar = codepoint - 0x10000;
    const high = 0xd800 + (scalar >> 10);
    const low = 0xdc00 + (scalar & 0x3ff);
    return `\\u${high.toString(16)}\\u${low.toString(16)}`;
  });
}

function exactKeys(value, wanted, label) {
  if (!isPlainObject(value)) fail(`${label}: not an object`);
  const got = new Set(Object.keys(value));
  const missing = [...wanted].filter((key) => !got.has(key));
  const extra = [...got].filter((key) => !wanted.has(key));
  if (missing.length || extra.length) {
    fail(`${label}: closed keys differ missing=${missing} extra=${extra}`);
  }
}

function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${label}: expected safe integer >= ${minimum}`);
  }
  return value;
}

function lowerSha(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label}: expected lowercase SHA-256`);
  }
}

function parseCanonical(filePath, label) {
  let raw;
  try {
    raw = fs.readFileSync(filePath);
  } catch (error) {
    fail(`${label}: cannot read ${filePath}: ${error.message}`);
  }
  let value;
  try {
    value = JSON.parse(raw.toString("utf8"));
  } catch (error) {
    fail(`${label}: malformed JSON ${filePath}: ${error.message}`);
  }
  if (!isPlainObject(value)) fail(`${label}: root is not an object`);
  const canonical = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  if (!raw.equals(canonical)) fail(`${label}: non-canonical compact JSON`);
  return { value, raw };
}

function safeShardPath(manifestPath, relative, rootReal) {
  if (
    typeof relative !== "string" ||
    relative.length === 0 ||
    relative.includes("\\") ||
    path.posix.isAbsolute(relative) ||
    path.posix.normalize(relative) !== relative ||
    relative.split("/").some((part) => part === "." || part === ".." || part === "")
  ) {
    fail(`manifest: unsafe/non-canonical shard path ${JSON.stringify(relative)}`);
  }
  const candidate = path.resolve(path.dirname(manifestPath), ...relative.split("/"));
  let real;
  try {
    real = fs.realpathSync(candidate);
  } catch (error) {
    fail(`manifest: shard path cannot resolve ${relative}: ${error.message}`);
  }
  if (real !== rootReal && !real.startsWith(`${rootReal}${path.sep}`)) {
    fail(`manifest: shard escapes authority root ${relative}`);
  }
  return real;
}

function feedObjectPrefix(hash, keys, values, stopKey, serializer) {
  hash.update("{");
  let emitted = 0;
  for (const key of keys) {
    if (key === stopKey) break;
    if (emitted) hash.update(",");
    hash.update(`${JSON.stringify(key)}:${serializer(values[key])}`);
    emitted += 1;
  }
  if (emitted) hash.update(",");
}

function feedObjectSuffix(hash, keys, values, startKey, serializer) {
  let after = false;
  for (const key of keys) {
    if (!after) {
      if (key === startKey) after = true;
      continue;
    }
    hash.update(`,${JSON.stringify(key)}:${serializer(values[key])}`);
  }
  hash.update("}");
}

function negativeProjection(vector) {
  const expected = isPlainObject(vector.expected) ? vector.expected : {};
  return {
    id: vector.id ?? null,
    kind: vector.kind ?? null,
    mode: vector.mode ?? null,
    negative_base: vector.negative_base ?? null,
    declared_mutation_fields: vector.declared_mutation_fields ?? null,
    first_reason: expected.d3s4_first_reason ?? null,
    faults: Array.isArray(vector.faults) ? vector.faults : [],
  };
}

function verify(manifestPath) {
  const absoluteManifest = path.resolve(manifestPath);
  const rootReal = fs.realpathSync(path.dirname(absoluteManifest));
  const { value: manifest } = parseCanonical(absoluteManifest, "manifest");
  exactKeys(manifest, MANIFEST_KEYS, "manifest");
  if (
    manifest.format !== MANIFEST_FORMAT ||
    manifest.version !== 1 ||
    manifest.expanded_format !== EXPANDED_FORMAT
  ) {
    fail("manifest: format/version/expanded_format mismatch");
  }
  for (const [key, wanted] of Object.entries(FIXED)) {
    if (manifest[key] !== wanted) {
      fail(`manifest: ${key} differs from independent fixed pin`);
    }
  }
  for (const key of [
    "expanded_content_sha256",
    "expanded_order_sha256",
    "expanded_negative_sha256",
    "expanded_canonical_sha256",
  ]) {
    lowerSha(manifest[key], `manifest.${key}`);
  }
  integer(manifest.max_shard_bytes, "manifest.max_shard_bytes", 1);
  if (manifest.max_shard_bytes > MAX_SHARD_BYTES) {
    fail("manifest: shard limit exceeds independent 10 MiB hard cap");
  }
  if (!isPlainObject(manifest.top_level) || "vectors" in manifest.top_level) {
    fail("manifest: top_level must be an object without vectors");
  }
  if (
    !Array.isArray(manifest.expanded_key_order) ||
    manifest.expanded_key_order.some((key) => typeof key !== "string") ||
    new Set(manifest.expanded_key_order).size !== manifest.expanded_key_order.length
  ) {
    fail("manifest: expanded_key_order is not a unique string array");
  }
  const expectedKeys = new Set([...Object.keys(manifest.top_level), "vectors"]);
  if (
    manifest.expanded_key_order.length !== expectedKeys.size ||
    manifest.expanded_key_order.some((key) => !expectedKeys.has(key))
  ) {
    fail("manifest: expanded_key_order is not the exact expanded key set");
  }
  if (!Array.isArray(manifest.shards) || manifest.shards.length === 0) {
    fail("manifest: shards must be a non-empty array");
  }

  const top = manifest.top_level;
  const canonicalKeys = manifest.expanded_key_order;
  const contentKeys = [...new Set([...Object.keys(top).filter((key) => key !== "content_sha256"), "vectors"])].sort();
  const canonicalHash = crypto.createHash("sha256");
  const contentHash = crypto.createHash("sha256");
  feedObjectPrefix(canonicalHash, canonicalKeys, top, "vectors", JSON.stringify);
  canonicalHash.update(`${JSON.stringify("vectors")}:[`);
  feedObjectPrefix(contentHash, contentKeys, top, "vectors", stableStringify);
  contentHash.update(`${JSON.stringify("vectors")}:[`);

  const orderHash = crypto.createHash("sha256");
  const negativeHash = crypto.createHash("sha256");
  negativeHash.update("[");
  let expectedStart = 0;
  let negativeCount = 0;
  let firstVector = true;
  let firstNegative = true;
  const seenPaths = new Set();

  for (let shardIndex = 0; shardIndex < manifest.shards.length; shardIndex += 1) {
    const entry = manifest.shards[shardIndex];
    const label = `manifest.shards[${shardIndex}]`;
    exactKeys(entry, ENTRY_KEYS, label);
    if (seenPaths.has(entry.path)) fail(`${label}: duplicate shard path`);
    seenPaths.add(entry.path);
    const shardPath = safeShardPath(absoluteManifest, entry.path, rootReal);
    const { value: shard, raw } = parseCanonical(shardPath, label);
    if (
      raw.length > manifest.max_shard_bytes ||
      raw.length > MAX_SHARD_BYTES ||
      entry.bytes !== raw.length ||
      entry.sha256 !== sha256(raw)
    ) {
      fail(`${label}: size or raw SHA-256 mismatch`);
    }
    exactKeys(shard, SHARD_KEYS, label);
    if (shard.format !== SHARD_FORMAT || shard.version !== 1) {
      fail(`${label}: shard format/version mismatch`);
    }
    integer(shard.start, `${label}.start`);
    integer(shard.count, `${label}.count`, 1);
    if (
      !Array.isArray(shard.vectors) ||
      shard.vectors.length !== shard.count ||
      entry.start !== shard.start ||
      entry.count !== shard.count ||
      shard.start !== expectedStart
    ) {
      fail(`${label}: non-contiguous start/count/vectors mismatch`);
    }
    const firstId = isPlainObject(shard.vectors[0]) ? shard.vectors[0].id : undefined;
    const lastId = isPlainObject(shard.vectors.at(-1)) ? shard.vectors.at(-1).id : undefined;
    if (entry.first_id !== firstId || entry.last_id !== lastId) {
      fail(`${label}: first/last id mismatch`);
    }
    for (let local = 0; local < shard.vectors.length; local += 1) {
      const vector = shard.vectors[local];
      if (!isPlainObject(vector)) fail(`${label}.vectors[${local}]: not an object`);
      const global = shard.start + local;
      const vectorJson = stableStringify(vector);
      if (!firstVector) {
        canonicalHash.update(",");
        contentHash.update(",");
        orderHash.update("\n");
      }
      canonicalHash.update(JSON.stringify(vector));
      contentHash.update(vectorJson);
      orderHash.update(
        `${global}\0${vector.id ?? ""}\0${vector.kind ?? ""}\0${vector.mode ?? ""}\0${
          vector.positive ? 1 : 0
        }`,
      );
      firstVector = false;
      if (vector.positive === false) {
        if (!firstNegative) negativeHash.update(",");
        negativeHash.update(pythonAsciiJson(negativeProjection(vector)));
        firstNegative = false;
        negativeCount += 1;
      }
    }
    expectedStart += shard.count;
  }

  canonicalHash.update("]");
  feedObjectSuffix(canonicalHash, canonicalKeys, top, "vectors", JSON.stringify);
  canonicalHash.update("\n");
  contentHash.update("]");
  feedObjectSuffix(contentHash, contentKeys, top, "vectors", stableStringify);
  negativeHash.update("]");

  const actual = {
    expanded_vector_count: expectedStart,
    expanded_content_sha256: contentHash.digest("hex"),
    expanded_order_sha256: orderHash.digest("hex"),
    expanded_negative_count: negativeCount,
    expanded_negative_sha256: negativeHash.digest("hex"),
    expanded_canonical_sha256: canonicalHash.digest("hex"),
  };
  if (top.content_sha256 !== actual.expanded_content_sha256) {
    fail("manifest: top_level.content_sha256 differs from recomputed content hash");
  }
  for (const [key, wanted] of Object.entries(FIXED)) {
    if (actual[key] !== wanted || actual[key] !== manifest[key]) {
      fail(
        `${key}: expanded recomputation mismatch ` +
          `actual=${String(actual[key])} manifest=${String(manifest[key])} fixed=${String(wanted)}`,
      );
    }
  }
  return {
    shards: manifest.shards.length,
    vectors: actual.expanded_vector_count,
    negatives: actual.expanded_negative_count,
    content: actual.expanded_content_sha256,
  };
}

function main(argv) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const defaultManifest = path.resolve(
    here,
    "..",
    "spec",
    "vectors",
    "domain-scan-crossrow-v1.json",
  );
  if (argv.length > 1 || (argv.length === 1 && ["-h", "--help"].includes(argv[0]))) {
    process.stderr.write(`usage: ${path.basename(process.argv[1])} [manifest.json]\n`);
    return argv.length === 1 ? 0 : 2;
  }
  try {
    const result = verify(argv[0] ?? defaultManifest);
    process.stdout.write(
      `d3s4 manifest: PASS shards=${result.shards} vectors=${result.vectors} ` +
        `negatives=${result.negatives} content=${result.content.slice(0, 16)}\n`,
    );
    return 0;
  } catch (error) {
    if (error instanceof CheckError) {
      process.stderr.write(`error: ${error.message}\n`);
      return 1;
    }
    process.stderr.write(`error: ${error.stack ?? error.message}\n`);
    return 2;
  }
}

process.exitCode = main(process.argv.slice(2));
