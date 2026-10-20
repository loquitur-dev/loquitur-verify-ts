// jsonIdentity, the key under which VG-1 finds two entries the same JSON value, against the
// reference: json_value_key of loquitur-schemas. The key never throws, keeps NaN and the infinities
// apart from null and from every finite number, reads 1, 1.0 and 1e0 as one value, and walks a value
// of any depth without the stack. Where the reference checkout is beside this one, the keys it writes
// for the same values are compared to these one by one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";
import { sibling } from "./siblings.ts";
import { jsonIdentity } from "../src/verdict-grounds.ts";

const SCHEMAS = sibling(
  "loquitur-schemas",
  [join(PACKAGE_DIR, "..", "loquitur-schemas")],
  join("src", "loquitur", "schemas", "validator.py"),
  "the loquitur-schemas checkout is not beside this one, so the reference key is not compared",
);

/** A value from a JSON text that may spell NaN, Infinity and -Infinity bare, as Python's json module reads them. */
function read(text: string): unknown {
  const marked = text.replace(/-Infinity|Infinity|NaN/g, (token) => `"${String.fromCharCode(92)}u0000${token}"`);
  const spelled: Record<string, number> = { "\u0000NaN": Number.NaN, "\u0000Infinity": Infinity, "\u0000-Infinity": -Infinity };
  return JSON.parse(marked, (_, v: unknown) => (typeof v === "string" && Object.hasOwn(spelled, v) ? spelled[v] : v));
}

const S = (text: string): string => JSON.stringify(text);
const BACKSLASH = String.fromCharCode(92);
const TEXTS = [
  "0", "-0", "-0.0", "1", "1.0", "1e0", "10", "1e1", "100", "1.5", "-1.5", "0.1", "0.5", "0.0001", "0.00001", "0.000123", "1e-7", "1.5e-10", "123456.789",
  "2.5e15", "4503599627370495.5", "1e15", "1e16", "1e21", "1e22", "1.7976931348623157e308", "5e-324", "1e400", "-1e400", "9007199254740991", "9007199254740993",
  "1152921504606846976", "123456789012345678901234567890", "0.30000000000000004", "100000000000000000000", "1.2345678901234567e-5",
  "true", "false", "null", '""', '"s"',
  S(`${String.fromCharCode(0, 31, 127)} é \u{1F600} "${BACKSLASH}`), S("\ud800"), S(String.fromCharCode(0xfffe)), S("\b\f\n\r\t"),
  "[]", "{}", "[[]]", "[{}]", "[1,2]", "[2,1]", '[1,"1"]', "[null]", "[[],[]]", "[NaN]", "[NaN,null]", "[null,null]", "[Infinity,-Infinity]", "[Infinity]", "[-Infinity]",
  "NaN", "Infinity", "-Infinity", '{"a":NaN}', '{"a":null}',
  '{"b":1,"a":2}', '{"a":2,"b":1}', '{"a":{"y":1,"x":[1.0,1e0]},"":0}', '{"__proto__":1}', '{"__proto__":{"__proto__":[]}}',
  '{"constructor":1,"toString":2,"hasOwnProperty":3}', '{"a":"b","c":["d",{"e":null}]}',
  `{${S("\u{1F600}")}:1,${S(String.fromCharCode(0xffff))}:2,"z":3}`, `{${S("\u0000")}:0,${S("\u0001")}:1}`, `{${S("é")}:1,"e":2,"f":3}`,
];

test("1, 1.0 and 1e0 are one value, and member order does not matter", () => {
  assert.equal(jsonIdentity(read("1")), jsonIdentity(read("1.0")));
  assert.equal(jsonIdentity(read("1")), jsonIdentity(read("1e0")));
  assert.equal(jsonIdentity(read("-0")), jsonIdentity(read("0")));
  assert.equal(jsonIdentity(read('{"a":1,"b":[2]}')), jsonIdentity(read('{"b":[2.0],"a":1e0}')));
  assert.notEqual(jsonIdentity(read("1")), jsonIdentity(read('"1"')));
  assert.notEqual(jsonIdentity(read("1")), jsonIdentity(read("1.5")));
  assert.notEqual(jsonIdentity(read("[1,2]")), jsonIdentity(read("[2,1]")));
});

test("NaN and the infinities are not null and not each other", () => {
  const keys = [Number.NaN, Infinity, -Infinity, null, 0, 1, -1, "nan", "inf"].map(jsonIdentity);
  assert.equal(new Set(keys).size, keys.length);
  assert.notEqual(jsonIdentity([Number.NaN, null]), jsonIdentity([null, null]));
  assert.notEqual(jsonIdentity([Infinity, -Infinity]), jsonIdentity([null, null]));
  assert.equal(jsonIdentity([Number.NaN]), jsonIdentity([0 / 0]));
});

test("__proto__ is a member name like any other", () => {
  const withProto = JSON.parse('{"__proto__":1}');
  assert.notEqual(jsonIdentity(withProto), jsonIdentity({}));
  assert.notEqual(jsonIdentity(withProto), jsonIdentity(JSON.parse('{"__proto__":2}')));
  assert.equal(jsonIdentity(withProto), jsonIdentity(JSON.parse('{"__proto__":1.0}')));
});

test("a value of any depth or width is keyed without the stack", () => {
  let deep: unknown = 0;
  for (let i = 0; i < 100000; i++) deep = [deep];
  assert.equal(jsonIdentity(deep).length, 2 + 2 * 100000 + 1);
  let deepObject: unknown = 0;
  for (let i = 0; i < 100000; i++) deepObject = { a: deepObject };
  assert.equal(jsonIdentity(deepObject).length, 2 + 6 * 100000 + 1);
  const wide = Array.from({ length: 300000 }, (_, i) => i);
  assert.ok(jsonIdentity(wide).startsWith("j:[0,1,2,"));
  assert.notEqual(jsonIdentity(wide), jsonIdentity([...wide, 0]));
});

test("a value JSON cannot hold is keyed, never thrown on", () => {
  const cycle: unknown[] = [];
  cycle.push(cycle);
  const keys = [undefined, () => 1, Symbol("x"), 10n, cycle, [undefined], [, 1]].map(jsonIdentity);
  assert.equal(keys[3], jsonIdentity(10));
  assert.notEqual(keys[0], jsonIdentity(null));
  assert.equal(new Set(keys).size, keys.length);
});

test("the reference key of loquitur-schemas is this key, value by value", SCHEMAS.options, () => {
  const python = process.env.LOQUITUR_PYTHON || "python";
  const script = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from loquitur.schemas.validator import json_value_key",
    "out = [json_value_key(json.loads(text)) for text in json.loads(sys.stdin.buffer.read().decode('utf-8'))]",
    "deep = 0",
    "for _ in range(100000):",
    "    deep = [deep]",
    "deep_object = 0",
    "for _ in range(100000):",
    "    deep_object = {'a': deep_object}",
    "out += [json_value_key(deep), json_value_key(deep_object)]",
    "sys.stdout.buffer.write(json.dumps(out).encode('ascii'))",
  ].join("\n");
  const run = spawnSync(python, ["-c", script, SCHEMAS.path("src")], { input: JSON.stringify(TEXTS), encoding: "utf8", maxBuffer: 64 << 20 });
  assert.equal(run.status, 0, run.stderr);
  const reference = JSON.parse(run.stdout) as string[];
  TEXTS.forEach((text, index) => assert.equal(jsonIdentity(read(text)), reference[index], text));
  let deep: unknown = 0;
  for (let i = 0; i < 100000; i++) deep = [deep];
  let deepObject: unknown = 0;
  for (let i = 0; i < 100000; i++) deepObject = { a: deepObject };
  assert.equal(jsonIdentity(deep), reference[TEXTS.length]);
  assert.equal(jsonIdentity(deepObject), reference[TEXTS.length + 1]);
});
