// The reason-code severity table is what the protocol's catalog generates, and the grounds rule
// derives a verdict from it exactly as verdict-grounds.md orders (VG-1 and VG-2 stop the check,
// VG-3 and VG-4 are evaluated together, and a verdict outside the vocabulary is a VG-3 finding
// made after VG-1 and VG-2, section 5).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";
import { sibling } from "./siblings.ts";
import { verdictGroundsViolations } from "../src/verdict-grounds.ts";
// @ts-ignore: a plain .mjs script; its one export is typed by use below
import { renderReasonCodeSeverity } from "../scripts/generate-reason-code-severity.mjs";

const PROTOCOL = sibling(
  "loquitur-protocol",
  [join(PACKAGE_DIR, "../loquitur-protocol/docs/specification"), join(PACKAGE_DIR, "../public/loquitur-protocol/docs/specification")],
  "reason-codes/v2.0/catalog.json",
  "sibling loquitur-protocol catalog absent",
);

test("src/reason-code-severity.generated.ts is what the protocol's catalog generates", PROTOCOL.options, () => {
  const catalog = JSON.parse(readFileSync(PROTOCOL.path("reason-codes/v2.0/catalog.json"), "utf8"));
  const schema = JSON.parse(readFileSync(PROTOCOL.path("schemas/registry_entry.schema.json"), "utf8"));
  const committed = readFileSync(join(PACKAGE_DIR, "src/reason-code-severity.generated.ts"), "utf8");
  assert.equal(committed, renderReasonCodeSeverity(catalog, schema));
  // Generation stops rather than guessing.
  const broken = structuredClone(catalog);
  broken.entries.INTEGRITY_OK.severity = "notice";
  assert.throws(() => renderReasonCodeSeverity(broken, schema), /no usable code and severity/);
  const narrowed = structuredClone(schema);
  narrowed.properties.reason_codes.items.enum.pop();
  assert.throws(() => renderReasonCodeSeverity(catalog, narrowed), /name different codes/);
});

test("the grounds rule derives the verdict from the highest cited severity", () => {
  const codes = (list: string[]) => list;
  const got = {
    "pass info": verdictGroundsViolations("PASS", codes(["INTEGRITY_OK"])),
    "warn info+warn": verdictGroundsViolations("WARN", codes(["INTEGRITY_OK", "MARK_STALE"])),
    "review only review": verdictGroundsViolations("REVIEW", codes(["NEEDS_REVIEW"])),
    "fail info+fail": verdictGroundsViolations("FAIL", codes(["INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"])),
    "pass fail": verdictGroundsViolations("PASS", codes(["AUTHORIZATION_ISSUER_KEY_REVOKED"])),
    "pass only warn": verdictGroundsViolations("PASS", codes(["MARK_STALE"])),
    "fail info": verdictGroundsViolations("FAIL", codes(["INTEGRITY_OK"])),
    "empty": verdictGroundsViolations("PASS", codes([])),
    "duplicate and unknown": verdictGroundsViolations("FAIL", codes(["NOT_A_CODE", "NOT_A_CODE"])),
    "unknown beside a known code": verdictGroundsViolations("PASS", codes(["INTEGRITY_OK", "NOT_A_CODE"])),
    "verdict pass lower case": verdictGroundsViolations("pass", codes(["INTEGRITY_OK"])),
    "verdict not a string": verdictGroundsViolations(7, codes(["INTEGRITY_OK"])),
    "verdict outside the vocabulary, no codes": verdictGroundsViolations("BANANA", codes([])),
    "verdict outside the vocabulary, an unknown code": verdictGroundsViolations("BANANA", codes(["NOT_A_CODE"])),
  };
  const v = (rule: string, field: string, code: string) => [{ rule, field, code }];
  assert.deepEqual(got, {
    "pass info": [],
    "warn info+warn": [],
    "review only review": [],
    "fail info+fail": [],
    "pass fail": [
      { rule: "VG-3", field: "verdict", code: "verdict_contradicts_grounds" },
      { rule: "VG-4", field: "verdict", code: "pass_without_affirmative_ground" },
    ],
    "pass only warn": [
      { rule: "VG-3", field: "verdict", code: "verdict_contradicts_grounds" },
      { rule: "VG-4", field: "verdict", code: "pass_without_affirmative_ground" },
    ],
    "fail info": v("VG-3", "verdict", "verdict_contradicts_grounds"),
    "empty": v("VG-1", "reason_codes", "reason_codes_absent"),
    "duplicate and unknown": v("VG-1", "reason_codes", "reason_codes_duplicated"),
    "unknown beside a known code": v("VG-2", "reason_codes", "reason_code_not_in_catalog"),
    "verdict pass lower case": [
      { rule: "VG-3", field: "verdict", code: "verdict_outside_vocabulary" },
      { rule: "VG-3", field: "verdict", code: "verdict_contradicts_grounds" },
    ],
    "verdict not a string": [
      { rule: "VG-3", field: "verdict", code: "verdict_outside_vocabulary" },
      { rule: "VG-3", field: "verdict", code: "verdict_contradicts_grounds" },
    ],
    "verdict outside the vocabulary, no codes": v("VG-1", "reason_codes", "reason_codes_absent"),
    "verdict outside the vocabulary, an unknown code": v("VG-2", "reason_codes", "reason_code_not_in_catalog"),
  });
});
