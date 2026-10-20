// The package's own tokenizer reads numbers by the JSON grammar of RFC 8259 section 6, as the
// platform parser does: no leading zero before another digit, no bare sign, no leading or trailing
// point, no empty exponent. Each spelling is checked against JSON.parse here, on a fresh string,
// so the two agree on every row.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseJsonStrict, JsonParseError } from "../src/canonical.ts";

const REFUSED = [
  '{"v":01}', '{"v":-01}', '{"v":00}', '{"v":00.5}', '[012]', '[-00]',
  '{"v":-}', '{"v":.5}', '{"v":1.}', '{"v":1e}', '{"v":1e+}', '{"v":+1}', '{"v":0x10}',
];
const ACCEPTED = ['{"v":0}', '{"v":-0}', '{"v":0.5}', '{"v":-0.5}', '{"v":10}', '{"v":1e5}', '{"v":1E-2}', '[0,1,20]'];

test("a number spelling the JSON grammar refuses is a contained parse error", () => {
  for (const text of REFUSED) {
    assert.throws(() => JSON.parse(text), SyntaxError, `platform parser accepts ${text}`);
    assert.throws(() => parseJsonStrict(text), JsonParseError, text);
  }
});

test("a number spelling the JSON grammar accepts decodes to the platform's value", () => {
  for (const text of ACCEPTED) {
    assert.deepEqual(parseJsonStrict(text), JSON.parse(text), text);
  }
});
