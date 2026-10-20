// Every tracked text file writes an invisible character as an escape.
//
// A test that pins the whitespace set W, a byte-order mark or a bidirectional override needs those
// code points, and a literal one inside a string literal is a character a reader of the file cannot
// see: review passes over it, a copy carries it into another file, and nothing tells it apart from
// a stray paste. A rule written down and not tested does not hold, so this test holds it, over
// every file git tracks, because tracked files are what a publication copies; README.md and the
// built sources reach the package tarball as well.
//
// An escape denotes the same code point: the values this suite asserts do not change, only the
// bytes of the source file. The rule covers what prints as nothing (the control, format and line
// or paragraph separators, every space that is not U+0020, every Default_Ignorable_Code_Point of
// Unicode, the variation selectors and the Hangul and Khmer fillers among them, and U+2800, the
// blank braille pattern) and the 66 noncharacters, which input strictness rule 9 refuses in any
// document. It does not cover unassigned or private-use code points, which print as a box rather
// than as nothing and which the canonicalization vectors carry as pinned data.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { relative, sep } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";
import { trackedFiles } from "./tracked-files.ts";

// Written as escapes here too, because this file is read by the rule it states.
const READABLE = new Set(["\t", "\n", "\r", " "]);
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Zs}\p{Default_Ignorable_Code_Point}\p{Noncharacter_Code_Point}\u2800]/u;

/** Every code point of `text` that prints as nothing, as `line:column: U+XXXX`. */
function invisible(text: string): string[] {
  const found: string[] = [];
  text.split("\n").forEach((line, number) => {
    [...line].forEach((character, column) => {
      if (!READABLE.has(character) && INVISIBLE.test(character)) {
        const point = character.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0");
        found.push(`${number + 1}:${column + 1}: U+${point}`);
      }
    });
  });
  return found;
}

test("the rule sees an invisible character and passes ordinary text", () => {
  assert.deepEqual(invisible("key_id\u00A0=\uFEFF\u2028"), ["1:7: U+00A0", "1:9: U+FEFF", "1:10: U+2028"]);
  assert.deepEqual(invisible("a tab\ta newline\na space and a hyphen -"), []);
  // The default-ignorable code points outside those categories, the fillers, U+2800 and the
  // noncharacters.
  const others = [0x034f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180b, 0x2800, 0x3164, 0xfe00, 0xfe0f, 0xffa0, 0xe0100];
  const nonchars = [0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x10ffff];
  for (const code of [...others, ...nonchars]) {
    const point = code.toString(16).toUpperCase().padStart(4, "0");
    assert.deepEqual(invisible(`a${String.fromCodePoint(code)}b`), [`1:2: U+${point}`], point);
  }
  for (const code of [0x00e9, 0x3042, 0x1f600, 0xfdcf, 0xfdf0, 0xfffd, 0x1fffd, 0x2801]) {
    assert.deepEqual(invisible(`a${String.fromCodePoint(code)}b`), [], code.toString(16));
  }
  assert.ok(trackedFiles().length > 10, "the sweep below would hold over almost nothing");
});

test("no tracked file holds a literal invisible character", () => {
  const findings: string[] = [];
  for (const path of trackedFiles()) {
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(path));
    } catch {
      continue; // not UTF-8 text: an archive, an image, a binary fixture
    }
    const name = relative(PACKAGE_DIR, path).split(sep).join("/");
    findings.push(...invisible(text).map((hit) => `${name}:${hit}`));
  }
  assert.deepEqual(findings, [], `a reader of the file cannot see these; write them as escapes: ${findings.join(", ")}`);
});
