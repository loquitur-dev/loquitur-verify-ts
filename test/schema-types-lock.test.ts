import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const lock = JSON.parse(readFileSync(new URL("../SCHEMA_TYPES_LOCK.json", import.meta.url), "utf8"));
const generated = readFileSync(new URL("../src/generated/loquitur-protocol.ts", import.meta.url));
const sha = createHash("sha256").update(generated).digest("hex");

test("generated SDK schema types are hash-locked", () => {
  assert.equal(sha, lock.sdk_sha256);
  assert.equal(lock.sdk_sha256, lock.source_sha256);
  // `unknown` is not a status (the resolution of LCP-0008 that the protocol's
  // docs/change-proposals.md records): it resolves to no registry verdict, and the proposal's
  // severity rule makes it unreachable.
  assert.deepEqual(lock.verification_statuses, ["pass", "warning", "review", "fail"]);
  assert.deepEqual(lock.registry_verdicts, ["PASS", "WARN", "REVIEW", "FAIL"]);
});
