// The verdict a registry entry commits to caps the result (registry-link.md section 6): FAIL gives
// FAIL, WARN and REVIEW give at least REVIEW, at the link check and at the authorization check,
// while checks.registry_link keeps reporting the link. The entries here agree with their receipts,
// so the link holds and the committed verdict is the only thing that decides. The authorization
// entries are signed with a key made for the run.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, ephemeralAuthorization, linkEntryFor, outcome } from "./bundle-kit.ts";

const STATUS_FOR: Record<string, string> = { PASS: "pass", WARN: "warning", REVIEW: "review", FAIL: "fail" };
// Reason codes whose highest severity derives each verdict: an entry's verdict must be the verdict
// of its grounds, so a committed WARN, REVIEW or FAIL cites codes that ground it, in the entry and
// in the receipt alike.
const GROUNDS: Record<string, string[]> = {
  PASS: ["INTEGRITY_OK"],
  WARN: ["INTEGRITY_OK", "MARK_STALE"],
  REVIEW: ["INTEGRITY_OK", "NEEDS_REVIEW"],
  FAIL: ["INTEGRITY_OK", "AUTHORIZATION_ISSUER_KEY_REVOKED"],
};

function withReceiptStatus(status: string, codes: string[]): Bundle {
  const b = Bundle.linkValid();
  b.edit("verification_receipt.json", (r) => { r.status = status; r.reason_codes = codes; });
  return b.seal();
}

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: at the link check the committed verdict caps the result and the link still holds`, () => {
    const got: Record<string, unknown> = {};
    for (const verdict of ["PASS", "WARN", "REVIEW", "FAIL"]) {
      const b = withReceiptStatus(STATUS_FOR[verdict]!, GROUNDS[verdict]!);
      got[verdict] = outcome(verify(b, { registryEntry: linkEntryFor(b, { verdict, reason_codes: GROUNDS[verdict] }) }), ["registry_link"]);
    }
    // A receipt that disagrees with the entry breaks the link, whatever the entry commits to.
    const disagreeing = withReceiptStatus("pass", GROUNDS.WARN!);
    got["WARN, receipt pass"] = outcome(verify(disagreeing, { registryEntry: linkEntryFor(disagreeing, { verdict: "WARN", reason_codes: GROUNDS.WARN }) }), ["registry_link"]);
    // FAIL has precedence over the review a WARN asks for.
    const broken = withReceiptStatus("warning", GROUNDS.WARN!);
    got["WARN, manifest_hash broken"] = outcome(
      verify(broken, { registryEntry: linkEntryFor(broken, { verdict: "WARN", reason_codes: GROUNDS.WARN, manifest_hash: `sha256:${"0".repeat(64)}` }) }), ["registry_link"]);
    assert.deepEqual(got, {
      PASS: { ...PASS, registry_link: true },
      WARN: { ...REVIEW, registry_link: true },
      REVIEW: { ...REVIEW, registry_link: true },
      FAIL: { ...FAIL, registry_link: true },
      "WARN, receipt pass": { ...FAIL, registry_link: false },
      "WARN, manifest_hash broken": { ...FAIL, registry_link: false },
    });
  });

  test(`${entryName}: at the authorization check a signed, authorized entry committing to FAIL fails and one committing to WARN reviews`, () => {
    const got: Record<string, unknown> = {};
    for (const verdict of ["FAIL", "WARN", "PASS"]) {
      const b = withReceiptStatus(STATUS_FOR[verdict]!, GROUNDS[verdict]!);
      got[verdict] = outcome(verify(b, ephemeralAuthorization(b, { verdict, reason_codes: GROUNDS[verdict] })), ["registry_link", "trust_registry", "registry_signature"]);
    }
    const trusted = { registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" };
    assert.deepEqual(got, {
      FAIL: { ...FAIL, ...trusted },
      WARN: { ...REVIEW, ...trusted },
      // No root pins the trust registry here, so a PASS entry is REVIEW (trust-root.md section 6).
      PASS: { ...REVIEW, ...trusted },
    });
  });
}
