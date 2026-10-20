// parseJsonStrict and readDocumentPath refuse what the Python verifier's strict loader
// (loquitur.verify.canonical.loads_json_bytes) refuses, at load: a lone surrogate or a noncharacter
// in a string or a member name (input strictness rules 4 and 9), a number that is not finite
// (rule 3) and an integer beyond 2^53 - 1 however it is spelled (rule 2). A document refused at
// load is `null` in readDocumentPath's answer, as the Python loader raises for it; a library that
// accepted it at load and refused it later would answer the same document differently from the
// Python helper a host calls.
//
// Each text is also run through the Python loader when the loquitur-verify-py checkout is beside
// this one, so the table is held to the Python loader, not only to itself.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JsonParseError, parseJsonStrict } from "../src/canonical.ts";
import { DOCUMENT_NOT_STRICT_JSON, readDocumentPath } from "../src/verify.ts";
import { sibling } from "./siblings.ts";

const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const VERIFY_PY = sibling(
  "loquitur-verify-py",
  [join(PACKAGE_DIR, "..", "loquitur-verify-py")],
  join("src", "loquitur", "verify", "canonical.py"),
  "the loquitur-verify-py checkout is not beside this one, so the Python strict loader is not run",
);

/** Each value, put as the member `v` of an object, with the rule the Python loader names for it. */
const REFUSED: Array<[string, string, string]> = [
  ["an escaped noncharacter", '"\\uffff"', "json_noncharacter"],
  ["a noncharacter written as itself", `"${String.fromCodePoint(0xfdd0)}"`, "json_noncharacter"],
  ["the last noncharacter, escaped as a pair", '"\\udbff\\udfff"', "json_noncharacter"],
  ["a lone high surrogate", '"\\ud800"', "json_lone_surrogate"],
  ["a lone low surrogate", '"a\\udc00"', "json_lone_surrogate"],
  ["2^53", "9007199254740992", "json_integer_outside_safe_range"],
  ["-2^53", "-9007199254740992", "json_integer_outside_safe_range"],
  ["2^53 written with a fraction", "9007199254740992.0", "json_integer_outside_safe_range"],
  ["1e16", "1e16", "json_integer_outside_safe_range"],
  ["1e21", "1e21", "json_integer_outside_safe_range"],
  ["1e400", "1e400", "non_finite_json_number"],
  ["-1e400", "-1e400", "non_finite_json_number"],
];
/** Member names, with the value 1. */
const REFUSED_NAMES: Array<[string, string, string]> = [
  ["a member name holding an escaped noncharacter", '"\\ufdd0"', "json_noncharacter"],
  ["a member name holding a lone surrogate", '"\\ud800"', "json_lone_surrogate"],
];
const ACCEPTED: Array<[string, string]> = [
  ["2^53 - 1", "9007199254740991"],
  ["-(2^53 - 1)", "-9007199254740991"],
  ["1e15", "1e15"],
  ["a surrogate pair", '"\\ud83d\\ude00"'],
  ["the replacement character", '"\\ufffd"'],
  ["0.1", "0.1"],
];

const refusedTexts: Array<[string, string, string]> = [
  ...REFUSED.map(([label, value, rule]): [string, string, string] => [label, `{"v":${value}}`, rule]),
  ...REFUSED_NAMES.map(([label, name, rule]): [string, string, string] => [label, `{${name}:1}`, rule]),
];
const acceptedTexts: Array<[string, string]> = ACCEPTED.map(([label, value]) => [label, `{"v":${value}}`]);

test("parseJsonStrict refuses each value the Python strict loader refuses, naming its rule", () => {
  for (const [label, text, rule] of refusedTexts) {
    assert.throws(() => parseJsonStrict(text), (err: unknown) => err instanceof JsonParseError && err.message.startsWith(`${rule}:`), label);
  }
});

test("parseJsonStrict accepts the values beside them", () => {
  for (const [label, text] of acceptedTexts) assert.doesNotThrow(() => parseJsonStrict(text), label);
});

test("readDocumentPath answers DOCUMENT_NOT_STRICT_JSON for a document the strict loader refuses, and the document otherwise", () => {
  const dir = mkdtempSync(join(tmpdir(), "strict-loader-"));
  try {
    for (const [index, [label, text]] of refusedTexts.entries()) {
      const path = join(dir, `refused-${index}.json`);
      writeFileSync(path, text, "utf8");
      assert.equal(readDocumentPath(path), DOCUMENT_NOT_STRICT_JSON, label);
    }
    for (const [index, [label, text]] of acceptedTexts.entries()) {
      const path = join(dir, `accepted-${index}.json`);
      writeFileSync(path, text, "utf8");
      assert.deepEqual(readDocumentPath(path), parseJsonStrict(text), label);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the Python strict loader gives the same answer and names the same rule for every text", VERIFY_PY.options, () => {
  const python = process.env.LOQUITUR_PYTHON || "python";
  const script = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from loquitur.verify.canonical import JsonLoadError, loads_json_bytes",
    "out = []",
    "for text in json.loads(sys.stdin.buffer.read().decode('utf-8')):",
    "    try:",
    "        loads_json_bytes(text.encode('utf-8', 'surrogatepass'), name='v')",
    "        out.append(None)",
    "    except JsonLoadError as exc:",
    "        out.append(str(exc))",
    "print(json.dumps(out))",
  ].join("\n");
  const texts = [...refusedTexts.map(([, text]) => text), ...acceptedTexts.map(([, text]) => text)];
  const run = spawnSync(python, ["-c", script, VERIFY_PY.path("src")], { input: JSON.stringify(texts), encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const answers = JSON.parse(run.stdout) as Array<string | null>;
  refusedTexts.forEach(([label, , rule], index) => {
    assert.ok(typeof answers[index] === "string" && answers[index]!.startsWith(`${rule}:`), `${label}: ${answers[index]}`);
  });
  acceptedTexts.forEach(([label], index) => assert.equal(answers[refusedTexts.length + index], null, label));
});
