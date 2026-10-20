import { test } from "node:test";
import assert from "node:assert/strict";
import { parseJsonStrict, JsonParseError } from "../src/canonical.js";

const rejects = (text: string) => assert.throws(() => parseJsonStrict(text), JsonParseError);

test("duplicate key at top level rejected", () => rejects('{"a": 1, "a": 2}'));
test("duplicate key nested rejected", () => rejects('{"o": {"k": 1, "k": 2}}'));
test("duplicate key inside array element rejected", () => rejects('[{"x": 1, "x": 1}]'));
test("escape-equivalent duplicate rejected (\\u0061 == a)", () => rejects('{"a": 1, "\\u0061": 2}'));
test("clean document parses", () => {
  assert.deepEqual(parseJsonStrict('{"a": 1, "b": {"a": 2}}'), { a: 1, b: { a: 2 } });
});
test("sibling objects may repeat key names", () => {
  assert.deepEqual(parseJsonStrict('[{"k": 1}, {"k": 2}]'), [{ k: 1 }, { k: 2 }]);
});
test("unicode strings with escapes survive strict parse", () => {
  assert.deepEqual(parseJsonStrict('{"s": "quote\\" brace } bracket ]"}'), { s: 'quote" brace } bracket ]' });
});
test("trailing garbage rejected", () => rejects('{"a": 1} x'));
