// Input rules, held to loquitur-protocol bundle-objects.md and canonicalization-and-hashing.md.
//
// The input rules are written there as text and tables: the whitespace set W, the portable
// member-name rule, the nesting bound, calendar instants, both envelope names, and a canonical
// input that is present and unreadable. Each table and number is read from the sibling checkout and
// checked against this verifier: W against every Unicode code point, the grammar and the calendar
// against every row of their tables, the nesting bound at the bound and one past it, the rest
// through the three entries.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, outcome } from "./bundle-kit.ts";
import { code, readSpecification, specification, table } from "./spec-tables.ts";
import { nonBlankString } from "../src/whitespace.ts";
import { isCalendarInstant } from "../src/instant.ts";
import { memberNameValid } from "../src/verify-core.ts";

const BUNDLE_OBJECTS = specification("bundle-objects.md");
const HASHING = specification("canonicalization-and-hashing.md");
const flat = (text: string) => text.replace(/\s+/g, " ");
const nested = (depth: number) => "[".repeat(depth) + "0" + "]".repeat(depth);

test("the whitespace set W is the one this verifier uses", BUNDLE_OBJECTS.options, () => {
  const rows = table(readSpecification(BUNDLE_OBJECTS, "bundle-objects.md"), ["W"]);
  const specified = new Set<number>();
  for (const row of rows) {
    const match = /^U\+([0-9A-F]{4,6})(?: to U\+([0-9A-F]{4,6}))?$/.exec(row["W"]!);
    assert.ok(match, row["W"]);
    for (let point = parseInt(match[1]!, 16); point <= parseInt(match[2] ?? match[1]!, 16); point++) specified.add(point);
  }
  const implemented = new Set<number>();
  for (let point = 0; point < 0x110000; point++) {
    if (point >= 0xd800 && point <= 0xdfff) continue;
    if (!nonBlankString(String.fromCodePoint(point))) implemented.add(point);
  }
  assert.deepEqual([...implemented].sort((a, b) => a - b), [...specified].sort((a, b) => a - b));
});

test("the portable member-name rule", BUNDLE_OBJECTS.options, () => {
  const rows = table(readSpecification(BUNDLE_OBJECTS, "bundle-objects.md"), ["member name", "a portable member name"]);
  const got = Object.fromEntries(rows.map((row) => [JSON.parse(code(row["member name"]!)), memberNameValid(JSON.parse(code(row["member name"]!)))]));
  const expected = Object.fromEntries(rows.map((row) => [JSON.parse(code(row["member name"]!)), row["a portable member name"] === "yes"]));
  assert.deepEqual(got, expected);
});

test("instants are calendar instants", HASHING.options, () => {
  const rows = table(readSpecification(HASHING, "canonicalization-and-hashing.md"), ["instant", "calendar instant"]);
  assert.deepEqual(
    Object.fromEntries(rows.map((row) => [code(row["instant"]!), isCalendarInstant(code(row["instant"]!))])),
    Object.fromEntries(rows.map((row) => [code(row["instant"]!), row["calendar instant"] === "yes"])),
  );
});

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: the nesting bound, and a receipt instant at the structure check`, HASHING.options, () => {
    const text = flat(readSpecification(HASHING, "canonicalization-and-hashing.md"));
    const bound = Number(/\*\*Nesting depth at most (\d+)\.\*\* A scalar has depth 0/.exec(text)![1]);
    assert.ok(text.includes(`A document of depth ${bound} is valid, and one of depth ${bound + 1} or more is invalid`));
    const withDeep = (depth: number) => {
      const b = Bundle.linkValid();
      const body = JSON.stringify(b.json("canonical_input.json"));
      return b.setBytes("canonical_input.json", `${body.slice(0, -1)},"deep":${nested(depth)}}`).seal();
    };
    // {"deep": <arrays of depth d>} has depth d + 1.
    assert.deepEqual(outcome(verify(withDeep(bound - 1))), PASS);
    assert.deepEqual(outcome(verify(withDeep(bound))), FAIL);
    const impossible = Bundle.linkValid().edit("verification_receipt.json", (r) => { r.verified_at = "2026-02-30T00:00:00Z"; }).seal();
    assert.deepEqual(outcome(verify(impossible)), FAIL);
  });

  test(`${entryName}: envelope.json is an ordinary member, and a canonical input present and unreadable`, BUNDLE_OBJECTS.options, () => {
    const text = flat(readSpecification(BUNDLE_OBJECTS, "bundle-objects.md"));
    assert.ok(text.includes("`envelope.json`, in particular, is an ordinary member name."));
    assert.ok(text.includes("both reference verifiers report `canonical_input_present` `true`, `p1_input_hash` `false` and `p1_sha256` `false`"));
    // Undeclared, envelope.json beside the envelope is an extra member: REVIEW, and the envelope
    // holds.
    const both = Bundle.linkValid().seal();
    both.setBytes("envelope.json", both.bytes("envelope_env1.json"));
    const report = verify(both.seal());
    assert.deepEqual([outcome(report, ["envelope_links"]), report.review_reasons], [{ ...REVIEW, envelope_links: true }, ["bundle_extra_files"]]);
    const unreadable = Bundle.linkValid().setBytes("canonical_input.json", "[1]").seal();
    assert.deepEqual(outcome(verify(unreadable), ["canonical_input_present", "p1_input_hash", "p1_sha256", "envelope_links"]), {
      ...FAIL, canonical_input_present: true, p1_input_hash: false, p1_sha256: false, envelope_links: true,
    });
  });
}
