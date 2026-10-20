// The depth limit is a rule, not a property of the host: under a stack a fifth of Node's default
// (--stack-size=200), a canonical input 64 levels deep still passes, and 65 and 20000 levels
// still fail with a report. Without the limit, the outcome would be whatever the stack allowed: a
// deep input would pass, or the parser would run out of stack and the input count as absent.
// The same holds for a document a host reads with readDocumentPath or parses with
// parseJsonStrict, under a small stack and under one four times Node's default: 64 levels is a
// document and 65 or more is DOCUMENT_NOT_STRICT_JSON, a JsonParseError from the parser, whatever
// the stack.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { FAIL, PACKAGE_DIR, PASS, TEST_DIR } from "./bundle-kit.ts";

for (const stackSize of [200, 4000]) {
  test(`the depth outcome does not depend on the stack size (--stack-size=${stackSize})`, () => {
    const child = spawnSync(process.execPath, [`--stack-size=${stackSize}`, "--import", "tsx", join(TEST_DIR, "depth-probe.ts")], {
      cwd: PACKAGE_DIR, encoding: "utf8", timeout: 120_000, env: { ...process.env, NODE_OPTIONS: "" },
    });
    assert.equal(child.status, 0, child.stderr);
    const rejected = { ...FAIL, canonical_input_present: true, p1_input_hash: false };
    const refused = { read: "not strict JSON", parsed: "JsonParseError" };
    assert.deepEqual(JSON.parse(child.stdout), {
      bundles: {
        64: { ...PASS, canonical_input_present: true, p1_input_hash: true },
        65: rejected,
        20000: rejected,
      },
      documents: { 64: { read: "document", parsed: "parsed" }, 65: refused, 5000: refused, 20000: refused },
    });
  });
}
