// The words of this package's human-readable output, held to an explicit list.
//
// What the package says in prose (the message of an error it throws, the message of a report error,
// any text a caller may show a person) is written in the string literals of src/. A message that
// called a bundle "verified" or a key "trusted" where the check behind it establishes less would be
// read as more than the verifier found. So every occurrence, in any letter case, of the words
// valid, validated, verified, authentic, authenticated, trusted, genuine, certified and guaranteed
// in a string literal or a template text of src/ must be one of the phrases listed below, each with
// the reason it claims no more than its check. A new occurrence fails this test until it is
// reviewed and listed; a listed phrase that is gone fails it too, so the list stays exact.
//
// Whole words only: report codes such as AUTHORIZATION_VERIFIED, ROOT_SIGNATURE_VALID or
// trust_registry_root_signature_verified are names of the protocol's vocabularies and members, not
// prose, and are fixed by the specification; "invalid" and "unverified" claim nothing positive.
// Comments are not output and are not read.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import { PACKAGE_DIR } from "./bundle-kit.ts";

const WORDS = /\b(valid|validated|verified|authentic|authenticated|trusted|genuine|certified|guaranteed)\b/i;

/** Each allowed occurrence: the file, and the exact text of the literal (or template text) holding it. */
const ALLOWED: Array<{ file: string; text: string }> = [
  {
    // A negative statement of fact about the input: a lone surrogate encodes no Unicode scalar
    // value, which is exactly what the check that throws this tested.
    file: "src/canonical.ts",
    text: ": lone high surrogate is not valid Unicode",
  },
  {
    // As above, for a low surrogate with no high surrogate before it.
    file: "src/canonical.ts",
    text: ": lone low surrogate is not valid Unicode",
  },
];

/** Every string literal and template text of a TypeScript source that holds one of the words. */
function wordingIn(fileName: string, source: string): string[] {
  const out: string[] = [];
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const visit = (node: ts.Node) => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      if (WORDS.test(node.text)) out.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : name.endsWith(".ts") ? [path] : [];
  });
}

const key = (file: string, text: string) => `${file}: ${JSON.stringify(text)}`;

test("every claim word in the package's output is a listed, reviewed phrase", () => {
  const found: string[] = [];
  const files = sources(join(PACKAGE_DIR, "src"));
  assert.ok(files.length >= 10, `only ${files.length} source files read`);
  for (const path of files) {
    const file = relative(PACKAGE_DIR, path).split("\\").join("/");
    for (const text of wordingIn(file, readFileSync(path, "utf8"))) found.push(key(file, text));
  }
  assert.deepEqual(found.sort(), ALLOWED.map(({ file, text }) => key(file, text)).sort());
});

test("the scan reads output text, in any letter case, and not comments or codes", () => {
  const planted = [
    "// The bundle is verified; a comment is not output.",
    'const code = "AUTHORIZATION_VERIFIED";',
    'const note = "trust_registry_root_signature_verified";',
    'const negative = "the value is invalid and unverified";',
    'throw new Error("the bundle is Verified");',
    "throw new Error(`issuer ${id} is trusted`);",
    "const m = `key ${id}: GENUINE`;",
  ].join("\n");
  assert.deepEqual(wordingIn("src/planted.ts", planted), ["the bundle is Verified", " is trusted", ": GENUINE"]);
});
