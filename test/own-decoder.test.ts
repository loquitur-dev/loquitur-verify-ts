// The strict parser decodes with this package's own tokenizer (canonical.ts decodeJson), and
// input strictness is I-JSON under RFC 8785 (canonicalization-and-hashing.md, "Input strictness":
// no excess precision, exponent forms, rule 6's base case, rule 9's noncharacters).
//
// Node.js 24's JSON.parse has decoded a member name differently after an earlier document in the
// same process (the escaped `é` read as `\`); a verdict that rests on it is not a function of
// the bundle. These tests hold the decoder to the text alone.
import { test } from "node:test";
import assert from "node:assert/strict";
import { JsonParseError, canonicalJsonBytes, parseJsonStrict } from "../src/canonical.ts";
import { jsonValueViolatesStrictness } from "../src/json-strictness.ts";

function strict(text: string): boolean {
  try {
    return !jsonValueViolatesStrictness(parseJsonStrict(text));
  } catch (err) {
    if (err instanceof JsonParseError) return false;
    throw err;
  }
}

test("the parser never calls the host's JSON.parse", () => {
  const original = JSON.parse;
  JSON.parse = () => {
    throw new Error("JSON.parse called");
  };
  try {
    assert.deepEqual(parseJsonStrict('{"a":[1,"\\u00e9",{"b":null}],"c":true}'), { a: [1, "é", { b: null }], c: true });
  } finally {
    JSON.parse = original;
  }
});

test("a member name decodes the same after any earlier document", () => {
  const victim = '{"":"","\\u00e9":""}';
  const before = Buffer.from(canonicalJsonBytes(parseJsonStrict(victim))).toString("hex");
  for (const poison of ['{"":1,"\\\\":2}', '{"\\\\":1}', '["\\\\","\\u00a0"]']) {
    JSON.parse(poison);
    parseJsonStrict(poison);
  }
  const value = parseJsonStrict(victim) as Record<string, unknown>;
  assert.deepEqual(Object.keys(value), ["", "é"]);
  assert.equal(Buffer.from(canonicalJsonBytes(value)).toString("hex"), before);
});

test("numbers: no excess precision, exponent forms read by value", () => {
  const cases: Array<[string, boolean]> = [
    ["0.1", true], ["1.0", true], ["1e0", true], ["1E2", true], ["-0", true], ["100", true], ["1e-7", true],
    ["2.0000000000000001", false], ["4.9e-325", false], ["0.30000000000000004441", false],
    ["9007199254740992.5", false], ["9007199254740993", false], ["1.5e300", false], ["1e400", false],
  ];
  for (const [spelling, valid] of cases) assert.equal(strict(`{"v":${spelling}}`), valid, spelling);
  assert.equal((parseJsonStrict('{"v":1E2}') as { v: number }).v, 100);
});

test("numbers: the leading-zero spellings are outside the grammar", () => {
  for (const spelling of ["01", "-01", "00", "-00.5", "1.", ".5", "+1", "1e", "0x10"]) {
    assert.throws(() => parseJsonStrict(`{"v":${spelling}}`), JsonParseError, spelling);
  }
});

test("rule 9: noncharacters are refused, literal or escaped, in a value or a member name", () => {
  for (const text of ['{"v":"\\ufdd0"}', '{"\\ufdef":1}', '{"v":"\uffff"}', '{"v":"\\ufffe"}', '{"v":"\\ud83f\\udffe"}', '{"v":"\u{10FFFF}"}']) {
    assert.equal(strict(text), false, text);
  }
  assert.equal(strict('{"v":"\\ufdcf\\ufdf0\\ufffd"}'), true);
});

test("rule 7: a leading byte-order mark is refused, U+FEFF inside a string is a scalar value", () => {
  assert.equal(strict('\ufeff{"v":1}'), false);
  assert.equal(strict('{"v":"\\ufeff"}'), true);
  assert.equal(strict('{"v":"\ufeff"}'), true);
});

test("rule 6: an empty container has depth 1, so 64 levels ending in [] pass and 65 ending in {} do not", () => {
  assert.equal(strict("[".repeat(63) + "[]" + "]".repeat(63)), true);
  assert.equal(strict("[".repeat(64) + "{}" + "]".repeat(64)), false);
  assert.equal(strict("[".repeat(64) + "1" + "]".repeat(64)), true);
  assert.equal(strict('{"v":"' + "[".repeat(200) + '"}'), true);
});

test("an unterminated string is a parse error, decided in linear time", () => {
  const text = '{"v":"' + "\\\\".repeat(400000);
  const started = Date.now();
  assert.throws(() => parseJsonStrict(text), JsonParseError);
  assert.ok(Date.now() - started < 2000);
});

test("the grammar: control characters, escapes, literals and trailing text", () => {
  assert.throws(() => parseJsonStrict('{"v":"a\nb"}'), JsonParseError);
  assert.throws(() => parseJsonStrict('{"v":"\\x41"}'), JsonParseError);
  assert.throws(() => parseJsonStrict('{"v":"\\u12"}'), JsonParseError);
  assert.throws(() => parseJsonStrict('{"v":tru}'), JsonParseError);
  assert.throws(() => parseJsonStrict('{"v":1} x'), JsonParseError);
  assert.throws(() => parseJsonStrict('{"a":1,"\\u0061":2}'), JsonParseError);
  assert.deepEqual(parseJsonStrict(' {"s":"\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041"} '), { s: '"\\/\b\f\n\r\tA' });
  const proto = parseJsonStrict('{"__proto__":{"x":1}}') as Record<string, unknown>;
  assert.ok(Object.prototype.hasOwnProperty.call(proto, "__proto__"));
  assert.equal(Object.getPrototypeOf(proto), Object.prototype);
});
