// Malformed protocol input must fail closed at the parsing boundary.
//
// This package's verifier API takes already-parsed objects, so a non-JSON registry entry
// can never reach it: rejection has to happen in the JSON boundary the consumer uses.
// This is the layer the shared verify.json parity matrix cannot express (Python's CLI
// loads files, this API does not), so it is pinned here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseJsonStrict } from "../src/canonical.ts";
import { parseRegistryEntry, parseTrustRegistry } from "../src/protocol-input.ts";

const tv = join(dirname(fileURLToPath(import.meta.url)), "../test-vectors");

test("a non-JSON registry entry is rejected at the parse boundary", () => {
  const raw = readFileSync(join(tv, "link_malformed_registry_entry.json"), "utf-8");
  assert.throws(() => parseJsonStrict(raw));
});

test("non-object protocol inputs fail closed rather than throwing", () => {
  for (const value of [null, 42, "string", true, [], undefined]) {
    const entry = parseRegistryEntry(value as never);
    assert.equal(entry.ok, false, `registry entry accepted ${JSON.stringify(value)}`);
    const trust = parseTrustRegistry(value as never);
    assert.equal(trust.ok, false, `trust registry accepted ${JSON.stringify(value)}`);
  }
});
