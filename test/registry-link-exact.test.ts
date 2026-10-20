// The link check compares the receipt and the registry entry exactly: reason_codes as a multiset
// (order is free, multiplicity is not), strings without trimming, policy_version as the entry's
// semver MAJOR against the receipt's integer. Each case edits the receipt, reseals the bundle, and
// builds an entry whose manifest and receipt hashes match what is on disk, so the field under test
// is the only thing that differs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, linkEntryFor, outcome } from "./bundle-kit.ts";

const BOTH = ["AUTHORIZATION_VERIFIED", "INTEGRITY_OK"];

type Case = { name: string; receipt: (r: any) => void; entry?: Record<string, unknown>; expected: object };
const CASES: Array<Case & { locks?: Case[] }> = [
  { name: "a NUL-joined code against the two codes", receipt: (r) => { r.reason_codes = ["AUTHORIZATION_VERIFIED\u0000INTEGRITY_OK"]; },
    entry: { reason_codes: BOTH }, expected: { ...FAIL, registry_link: false },
    locks: [{ name: "a comma-joined code against the two codes", receipt: (r) => { r.reason_codes = ["AUTHORIZATION_VERIFIED,INTEGRITY_OK"]; },
      entry: { reason_codes: BOTH }, expected: { ...FAIL, registry_link: false } }] },
  { name: "a duplicated code in the receipt", receipt: (r) => { r.reason_codes = ["INTEGRITY_OK", "INTEGRITY_OK"]; },
    expected: { ...FAIL, registry_link: false },
    locks: [{ name: "the same two codes in another order", receipt: (r) => { r.reason_codes = [...BOTH].reverse(); },
      entry: { reason_codes: BOTH }, expected: { ...PASS, registry_link: true } }] },
  { name: "a padded code in the receipt", receipt: (r) => { r.reason_codes = [" INTEGRITY_OK "]; },
    expected: { ...FAIL, registry_link: false } },
  { name: "a padded policy_id in the receipt", receipt: (r) => { r.policy_id = ` ${r.policy_id}`; },
    expected: { ...FAIL, registry_link: false },
    locks: [{ name: "the fixture as it is", receipt: () => {}, expected: { ...PASS, registry_link: true } }] },
  { name: "a padded policy_id in the entry", receipt: () => {},
    entry: { policy_id: " loquitur.policy.property.demo" }, expected: { ...FAIL, registry_link: false } },
  { name: "a receipt policy_version spelled as a string", receipt: (r) => { r.policy_version = "1"; },
    expected: { ...FAIL, registry_link: false } },
];

for (const [entryName, verify] of ENTRIES) {
  for (const c of CASES) {
    // A case that inexact comparison also gets right rides along with one it gets wrong, so
    // every test here fails without exact comparison.
    const title = [c, ...(c.locks ?? [])].map((x) => x.name).join("; ");
    test(`${entryName}: link with ${title}`, () => {
      for (const x of [c, ...(c.locks ?? [])]) {
        const b = Bundle.linkValid();
        b.edit("verification_receipt.json", x.receipt);
        b.seal();
        const report = verify(b, { registryEntry: linkEntryFor(b, x.entry) });
        assert.deepEqual(outcome(report, ["registry_link"]), x.expected, x.name);
      }
    });
  }
}
