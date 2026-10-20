// Properties of member names (bundle-objects.md section 2; canonicalization-and-hashing.md
// section 7): memberNameValid agrees with a model written in this file from rules 1 to 4 of the
// portable member-name rule, and the member-name fold reads A to Z as a to z and changes nothing
// else, so it is idempotent and keeps every other UTF-16 unit where it was.
//
// Seed, budget and generators: test/property-kit.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { foldMemberName, isSelfDeclaration, memberNameValid } from "../src/verify-core.ts";
import { check } from "./property-kit.ts";

const PORTABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
const DEVICES = ["con", "prn", "aux", "nul", ...[1, 2, 3, 4, 5, 6, 7, 8, 9].flatMap((n) => [`com${n}`, `lpt${n}`])];

/** A to Z read as a to z, one UTF-16 unit at a time, nothing else changed. */
function modelFold(name: string): string {
  let out = "";
  for (let i = 0; i < name.length; i++) {
    const unit = name.charCodeAt(i);
    out += String.fromCharCode(unit >= 0x41 && unit <= 0x5a ? unit + 0x20 : unit);
  }
  return out;
}

/** The portable member-name rule, rules 1 to 4, as bundle-objects.md section 2 states them. */
function modelPortable(name: string): boolean {
  // Rule 4: the whole name is at most 255 bytes (UTF-8; a name that is not text fails rule 1).
  if (new TextEncoder().encode(name).length > 255) return false;
  for (const segment of name.split("/")) {
    // Rule 1: every segment is non-empty and holds only the POSIX portable filename characters.
    if (segment.length === 0) return false;
    for (const ch of segment) if (!PORTABLE.includes(ch) || ch.length !== 1) return false;
    // Rule 2: no segment is `.` or `..`, ends with `.`, or begins with `-`.
    if (segment === "." || segment === ".." || segment.endsWith(".") || segment.startsWith("-")) return false;
    // Rule 3: the part before the first `.`, with ASCII case ignored, is not a device name.
    if (DEVICES.includes(modelFold(segment.split(".")[0]!))) return false;
  }
  return true;
}

const portableChar = fc.constantFrom(...PORTABLE);
const awkwardChar = fc.constantFrom(
  "a", "B", ".", "-", "_", " ", "\\", ":", "~", "*", "?", "<", "|", "\t", String.fromCharCode(0),
  String.fromCodePoint(0xe9), String.fromCodePoint(0x212a), String.fromCodePoint(0x130), String.fromCodePoint(0x17f),
  String.fromCodePoint(0xff21), String.fromCodePoint(0xfeff), String.fromCodePoint(0x1f600), String.fromCharCode(0xd800),
);
const segment = fc.oneof(
  { weight: 4, arbitrary: fc.string({ unit: portableChar, maxLength: 12 }) },
  { weight: 2, arbitrary: fc.constantFrom(".", "..", "...", "CON", "con.txt", "Lpt9.json", "com0", "COM10", "nul.", "-x", "x.", "aux.tar.gz", "prn1", "CONSOLE", "lpt", "Nul", "cOm7.a.b", ".hidden", "a-", "_") },
  { weight: 2, arbitrary: fc.string({ unit: fc.oneof(portableChar, awkwardChar), maxLength: 8 }) },
  { weight: 1, arbitrary: fc.string({ unit: portableChar, minLength: 60, maxLength: 140 }) },
);
const name = fc.oneof(
  { weight: 5, arbitrary: fc.array(segment, { minLength: 1, maxLength: 4 }).map((segments) => segments.join("/")) },
  { weight: 1, arbitrary: fc.string({ unit: "binary", maxLength: 20 }) },
);

test("memberNameValid agrees with the portable member-name rule, rules 1 to 4", () => {
  check(fc.property(name, (n) => assert.equal(memberNameValid(n), modelPortable(n), JSON.stringify(n))), 3000);
  // The bound, either side of it.
  for (const length of [254, 255, 256]) assert.equal(memberNameValid("a".repeat(length)), length <= 255, String(length));
  for (const value of [undefined, null, 1, ["a"], { name: "a" }]) assert.equal(memberNameValid(value), false);
});

test("the member-name fold changes only A to Z, and is idempotent", () => {
  const anyText = fc.oneof(fc.string({ unit: "binary", maxLength: 30 }), fc.string({ unit: fc.oneof(portableChar, awkwardChar), maxLength: 30 }));
  check(
    fc.property(anyText, (s) => {
      const folded = foldMemberName(s);
      assert.equal(folded, modelFold(s));
      assert.equal(foldMemberName(folded), folded);
      assert.equal(folded.length, s.length);
      for (let i = 0; i < s.length; i++) {
        const unit = s.charCodeAt(i);
        const upper = unit >= 0x41 && unit <= 0x5a;
        assert.equal(folded.charCodeAt(i), upper ? unit + 0x20 : unit);
      }
    }),
    3000,
  );
});

test("a files key is a self-declaration exactly when its fold is manifest.json or manifest.sha256", () => {
  // Spellings of the two names: each letter in either case, or swapped for a character that a
  // Unicode case mapping relates to a letter of them (U+0130 for i, U+017F for s, U+212A for k).
  const lookalikes: Record<string, string> = { i: String.fromCodePoint(0x130), s: String.fromCodePoint(0x17f), k: String.fromCodePoint(0x212a) };
  const spelling = fc
    .tuple(fc.constantFrom("manifest.json", "manifest.sha256", "manifest.jsonk"), fc.array(fc.nat(2), { minLength: 16, maxLength: 16 }))
    .map(([base, choices]) =>
      [...base].map((ch, i) => (choices[i] === 1 ? ch.toUpperCase() : choices[i] === 2 && lookalikes[ch] ? lookalikes[ch]! : ch)).join(""),
    );
  check(
    fc.property(fc.oneof(spelling, name), (key) => {
      const folded = modelFold(key);
      assert.equal(isSelfDeclaration(key), folded === "manifest.json" || folded === "manifest.sha256", JSON.stringify(key));
    }),
    2000,
  );
});
