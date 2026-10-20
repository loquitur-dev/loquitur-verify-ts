// summaryViolatedRules: the rules of verdict-grounds.md section 3 a verification summary violates,
// in rule order, with section 5's order (VG-1 and VG-2 are listed alone). The worked examples of
// section 8 and a case per rule are run here, and every case is also run through the reference
// checker, loquitur-schemas' verdict_grounds_errors, when that checkout is beside this one, so the
// two answer every case alike.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";
import { sibling } from "./siblings.ts";
import { summaryViolatedRules } from "../src/verdict-grounds.ts";
import { parseJsonStrict } from "../src/canonical.ts";

const SCHEMAS = sibling(
  "loquitur-schemas",
  [join(PACKAGE_DIR, "..", "loquitur-schemas")],
  join("src", "loquitur", "schemas", "verdict_grounds.py"),
  "the loquitur-schemas checkout is not beside this one, so the reference checker is not run",
);

const V = "loquitur.reason_codes.v1";
const CASES: Array<[string, unknown, string[]]> = [
  ["a conforming pass", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: [{ check_id: "integrity", status: "pass" }], reason_code_vocabulary_version: V }, []],
  ["a conforming fail with context", { status: "fail", reason_codes: ["AUTHORIZATION_ISSUER_KEY_REVOKED"], reason_context: [{ code: "AUTHORIZATION_ISSUER_KEY_REVOKED", observed: "revoked" }], reason_code_vocabulary_version: V }, []],
  ["a warning citing only a warn code", { status: "warning", reason_codes: ["FRESHNESS_WARNING"], reason_code_vocabulary_version: V }, []],
  ["context for a code not cited", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: ["integrity"], reason_context: [{ code: "FRESHNESS_WARNING" }] }, []],
  ["reason_codes empty", { status: "pass", reason_codes: [] }, ["VG-1"]],
  ["reason_codes absent", { status: "pass" }, ["VG-1"]],
  ["reason_codes a string", { status: "pass", reason_codes: "INTEGRITY_OK" }, ["VG-1"]],
  ["a code cited twice", { status: "pass", reason_codes: ["INTEGRITY_OK", "INTEGRITY_OK"], key_checks: ["integrity"] }, ["VG-1"]],
  ["an object cited twice", { status: "pass", reason_codes: [{ a: 1, b: 2 }, { b: 2, a: 1 }] }, ["VG-1"]],
  ["not an object", ["INTEGRITY_OK"], ["VG-1"]],
  ["a code outside the catalog", { status: "pass", reason_codes: ["INTEGRITY_OK", "NOT_A_REAL_CODE"], key_checks: ["integrity"] }, ["VG-2"]],
  ["a code that is not a string", { status: "pass", reason_codes: ["INTEGRITY_OK", 7] }, ["VG-2"]],
  ["a pass citing a fail code", { status: "pass", reason_codes: ["AUTHORIZATION_ISSUER_KEY_REVOKED"], key_checks: ["x"], reason_context: [{ code: "AUTHORIZATION_ISSUER_KEY_REVOKED" }] }, ["VG-3", "VG-4"]],
  ["a fail citing only an info code", { status: "fail", reason_codes: ["INTEGRITY_OK"] }, ["VG-3"]],
  ["a status outside the vocabulary", { status: "PASS", reason_codes: ["INTEGRITY_OK"], key_checks: ["x"] }, ["VG-3"]],
  ["a pass citing only a warn code, no key_checks", { status: "pass", reason_codes: ["FRESHNESS_WARNING"] }, ["VG-3", "VG-4", "VG-5"]],
  ["a pass with key_checks {}", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: {} }, ["VG-5"]],
  ["a pass with key_checks null", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: null }, ["VG-5"]],
  ["a pass with no key_checks", { status: "pass", reason_codes: ["INTEGRITY_OK"] }, ["VG-5"]],
  ["a fail with no context", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"] }, ["VG-6"]],
  ["a fail with context for another code only", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"], reason_context: [{ code: "INTEGRITY_OK" }] }, ["VG-6"]],
  ["a context entry outside the catalog", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"], reason_context: [{ code: "INTEGRITY_OFFLINE_FAIL" }, { code: "NOT_A_REAL_CODE" }] }, ["VG-7"]],
  ["a context entry whose code is not a string", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: ["x"], reason_context: [{ code: 7 }] }, ["VG-7"]],
  ["VG-6 and VG-7 together", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"], reason_context: [{ code: "NOT_A_REAL_CODE" }] }, ["VG-6", "VG-7"]],
  // Section 1: the rules apply to any JSON value, valid against the schema or not.
  ["a pass with key_checks a string", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: "integrity" }, ["VG-5"]],
  ["a pass with key_checks true", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: true }, ["VG-5"]],
  ["a pass with key_checks false", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: false }, ["VG-5"]],
  ["a pass with key_checks a number", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: 1 }, ["VG-5"]],
  ["a fail with key_checks a string", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"], key_checks: "", reason_context: [{ code: "INTEGRITY_OFFLINE_FAIL" }] }, []],
  ["a context entry without a code", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"], reason_context: [{ code: "INTEGRITY_OFFLINE_FAIL" }, { observed: "x" }] }, ["VG-7"]],
  ["a context entry that is not an object", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"], reason_context: [{ code: "INTEGRITY_OFFLINE_FAIL" }, "INTEGRITY_OFFLINE_FAIL"] }, ["VG-7"]],
  ["a context entry that is null", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: ["x"], reason_context: [null] }, ["VG-7"]],
  ["a context entry that is an array", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: ["x"], reason_context: [[{ code: "INTEGRITY_OK" }]] }, ["VG-7"]],
  ["a context entry whose code is null", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: ["x"], reason_context: [{ code: null }] }, ["VG-7"]],
  ["a context entry without a code, beside a fail it does not ground", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"], reason_context: [{}] }, ["VG-6", "VG-7"]],
  ["reason_context an object", { status: "fail", reason_codes: ["INTEGRITY_OFFLINE_FAIL"], reason_context: { code: "INTEGRITY_OFFLINE_FAIL" } }, ["VG-6"]],
  ["reason_context a string beside a pass", { status: "pass", reason_codes: ["INTEGRITY_OK"], key_checks: ["x"], reason_context: "NOT_A_REAL_CODE" }, []],
];

test("each case violates the rules verdict-grounds.md section 3 names, in rule order", () => {
  for (const [label, summary, expected] of CASES) assert.deepEqual(summaryViolatedRules(summary), expected, label);
});

// VG-1 compares entries as JSON values: three spellings of one number are one entry, cited three
// times; two numbers are two entries, neither a catalog code. VG-2 reads the catalog, never
// reason_code_vocabulary_version. NaN and the infinities cannot be spelled in JSON, so they are
// entries of the cases below built in code: JSON.stringify would write each of them as null.
const TEXT_CASES: Array<[string, string, string[]]> = [
  ["1, 1.0 and 1e0 cited beside a code are one entry", '{"status":"pass","reason_codes":["INTEGRITY_OK",1,1.0,1e0],"key_checks":["x"]}', ["VG-1"]],
  ["1 and 2 are two entries, neither a code", '{"status":"pass","reason_codes":["INTEGRITY_OK",1,2],"key_checks":["x"]}', ["VG-2"]],
  ["a vocabulary version that names another version is not read", '{"status":"pass","reason_codes":["INTEGRITY_OK"],"key_checks":["x"],"reason_code_vocabulary_version":"loquitur.reason_codes.v9"}', []],
  ["a vocabulary version that is a number is not read", '{"status":"pass","reason_codes":["INTEGRITY_OK"],"key_checks":["x"],"reason_code_vocabulary_version":7}', []],
  ["objects that differ in member order are one entry", '{"status":"pass","reason_codes":[{"a":1,"b":[2]},{"b":[2.0],"a":1e0}]}', ["VG-1"]],
  ["null and false are two entries", '{"status":"pass","reason_codes":[null,false]}', ["VG-2"]],
  ["a string and the number it spells are two entries", '{"status":"pass","reason_codes":["1",1]}', ["VG-2"]],
  ["a large safe integer and its fraction spelling are one entry", '{"status":"pass","reason_codes":[9007199254740991,9007199254740991.0,9.007199254740991e15]}', ["VG-1"]],
  ["__proto__ members are members like any other", '{"status":"pass","reason_codes":[{"__proto__":1},{"__proto__":2}]}', ["VG-2"]],
  ["the same __proto__ member twice is one entry", '{"status":"pass","reason_codes":[{"__proto__":1},{"__proto__":1.0}]}', ["VG-1"]],
];

test("entries are compared as JSON values, and the vocabulary version is not read", () => {
  for (const [label, text, expected] of TEXT_CASES) assert.deepEqual(summaryViolatedRules(parseJsonStrict(text)), expected, label);
});

test("NaN and the infinities are values of their own, not null", () => {
  const cited = (...codes: unknown[]) => summaryViolatedRules({ status: "pass", reason_codes: codes });
  assert.deepEqual(cited(Number.NaN, null), ["VG-2"]);
  assert.deepEqual(cited(Infinity, -Infinity), ["VG-2"]);
  assert.deepEqual(cited(Number.NaN, Number.NaN), ["VG-1"]);
  assert.deepEqual(cited(Infinity, Infinity), ["VG-1"]);
  assert.deepEqual(cited([Number.NaN], [null]), ["VG-2"]);
});

test("the reference checker in loquitur-schemas finds the same rules for every case, texts included", SCHEMAS.options, () => {
  const python = process.env.LOQUITUR_PYTHON || "python";
  const script = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from loquitur.schemas.verdict_grounds import verdict_grounds_errors",
    "RULES = {'reason_codes_absent': 'VG-1', 'reason_codes_duplicated': 'VG-1', 'reason_code_not_in_catalog': 'VG-2',",
    "         'verdict_outside_vocabulary': 'VG-3', 'status_contradicts_grounds': 'VG-3', 'pass_without_affirmative_ground': 'VG-4',",
    "         'pass_without_key_checks': 'VG-5', 'reason_context_missing': 'VG-6', 'reason_context_code_not_in_catalog': 'VG-7'}",
    "out = []",
    "for text in json.load(sys.stdin):",
    "    summary = json.loads(text)",
    "    rules = {RULES[error.split(':', 1)[0]] for error in verdict_grounds_errors(summary)}",
    "    out.append(sorted(rules))",
    "print(json.dumps(out))",
  ].join("\n");
  // Every case goes as the text the reference reads, so 1, 1.0 and 1e0 reach it as three spellings.
  const ALL: Array<[string, string, unknown, string[]]> = [
    ...CASES.map(([label, summary, expected]): [string, string, unknown, string[]] => [label, JSON.stringify(summary), summary, expected]),
    ...TEXT_CASES.map(([label, text, expected]): [string, string, unknown, string[]] => [label, text, parseJsonStrict(text), expected]),
  ];
  const run = spawnSync(python, ["-c", script, SCHEMAS.path("src")], { input: JSON.stringify(ALL.map(([, text]) => text)), encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const reference = JSON.parse(run.stdout) as string[][];
  assert.equal(reference.length, ALL.length);
  ALL.forEach(([label, , summary], index) => assert.deepEqual(summaryViolatedRules(summary), reference[index], label));
});
