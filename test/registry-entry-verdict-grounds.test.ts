// A registry entry's verdict is the verdict its reason codes derive (verdict-grounds.md VG-1 to
// VG-4 applied to the entry), as in the Python verifier.
//
// Without the rule, an entry with verdict PASS citing AUTHORIZATION_ISSUER_KEY_REVOKED (severity
// fail) would link at the link check and pass, and an entry committing to FAIL or WARN while citing
// only INTEGRITY_OK would hold its link and cap the run by a verdict its own grounds deny. The rule
// is part of the entry's contract, at the link and authorization checks: at least one code and none
// twice, every code in the catalog, the verdict equal to the verdict of the highest cited severity
// (info PASS, warn WARN, review REVIEW, fail FAIL), and a PASS citing an info-severity code. A
// violation is a failed entry: registry_link false, trust_registry null. Receipts here cite the
// same codes and the matching status, so the grounds are the only thing in question.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, ephemeralAuthorizationWith, linkEntryFor, outcome } from "./bundle-kit.ts";

const RECEIPT_STATUS: Record<string, string> = { PASS: "pass", WARN: "warning", REVIEW: "review", FAIL: "fail" };

const ROWS: Record<string, [string, string[], Record<string, unknown>]> = {
  "pass-citing-a-fail-code": ["PASS", ["AUTHORIZATION_ISSUER_KEY_REVOKED"], { ...FAIL, registry_link: false }],
  "pass-citing-a-review-code": ["PASS", ["NEEDS_REVIEW"], { ...FAIL, registry_link: false }],
  "pass-citing-info-and-warn": ["PASS", ["INTEGRITY_OK", "MARK_STALE"], { ...FAIL, registry_link: false }],
  "pass-citing-only-warn": ["PASS", ["MARK_STALE"], { ...FAIL, registry_link: false }],
  "fail-citing-only-info": ["FAIL", ["INTEGRITY_OK"], { ...FAIL, registry_link: false }],
  "warn-citing-only-info": ["WARN", ["INTEGRITY_OK"], { ...FAIL, registry_link: false }],
  "review-citing-a-fail-code": ["REVIEW", ["AUTHORIZATION_ISSUER_KEY_REVOKED"], { ...FAIL, registry_link: false }],
  "review-citing-only-warn": ["REVIEW", ["MARK_STALE"], { ...FAIL, registry_link: false }],
  "pass-citing-info": ["PASS", ["INTEGRITY_OK"], { ...PASS, registry_link: true }],
  "pass-citing-two-info": ["PASS", ["INTEGRITY_OK", "REQUIRED_CLAIMS_PRESENT"], { ...PASS, registry_link: true }],
  "warn-citing-info-and-warn": ["WARN", ["INTEGRITY_OK", "MARK_STALE"], { ...REVIEW, registry_link: true }],
  "review-citing-info-warn-review": ["REVIEW", ["INTEGRITY_OK", "MARK_STALE", "NEEDS_REVIEW"], { ...REVIEW, registry_link: true }],
  "fail-citing-a-fail-code": ["FAIL", ["INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"], { ...FAIL, registry_link: true }],
};

function grounded(verdict: string, codes: string[]): Bundle {
  const b = Bundle.linkValid();
  b.edit("verification_receipt.json", (r) => { r.status = RECEIPT_STATUS[verdict]; r.reason_codes = codes; });
  return b.seal();
}

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: an entry whose verdict is not the verdict of its grounds fails its contract`, () => {
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const [label, [verdict, codes, want]] of Object.entries(ROWS)) {
      const b = grounded(verdict, codes);
      got[label] = outcome(verify(b, { registryEntry: linkEntryFor(b, { verdict, reason_codes: codes }) }), ["registry_link"]);
      expected[label] = { ...want };
    }
    // At authorization the entry fails before any trust conclusion.
    const b = grounded("PASS", ["AUTHORIZATION_ISSUER_KEY_REVOKED"]);
    const authRun = ephemeralAuthorizationWith(b, { entry: (e) => { e.reason_codes = ["AUTHORIZATION_ISSUER_KEY_REVOKED"]; } });
    got["authorization-pass-citing-a-fail-code"] = outcome(verify(b, authRun), ["registry_link", "trust_registry", "registry_signature"]);
    expected["authorization-pass-citing-a-fail-code"] = { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" };
    assert.deepEqual(got, expected);
  });
}
