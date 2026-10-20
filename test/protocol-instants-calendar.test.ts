// Every instant of every protocol document is a calendar instant, whenever the document is loaded,
// as in the Python verifier.
//
// The schemas' instant pattern admits February 30, April 31, February 29 of a common year, second
// 60 and year 0000. Such a value is refused wherever the document is loaded, not only where it is
// evaluated: a receipt dated February 30, an entry issued on February 30, and a trust registry
// issued on February 30 or carrying such a revoked_at each fail. The calendar belongs to each
// document's contract, with the document's outcome: a receipt fails the run (registry_link null
// below the link check, false at the link check), a registry entry fails its contract
// (registry_link false, trust_registry null), a trust registry is refused (trust_registry false).
// Leap days of leap years are instants.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, SMALL_Y_POINT, ephemeralAuthorizationWith, linkEntryFor, outcome } from "./bundle-kit.ts";
import { receiptContractErrors } from "../src/receipt-contract.ts";
import { RECEIPT_CONTRACT } from "../src/receipt-contract.generated.ts";
import { PROTOCOL_INSTANT_SOURCE } from "../src/instant.ts";

const NOT_INSTANTS: Record<string, string> = {
  feb30: "2026-02-30T12:00:00Z",
  apr31: "2026-04-31T12:00:00Z",
  "feb29-common-year": "2026-02-29T12:00:00Z",
  second60: "2026-04-29T12:00:60Z",
  year0000: "0000-01-01T00:00:00Z",
};
const LEAP_DAY = "2028-02-29T12:00:00Z";
const CHECKS = ["registry_link", "trust_registry", "registry_signature"];

test("the receipt contract's verified_at carries the protocol instant pattern the calendar rule is keyed to", () => {
  assert.equal(RECEIPT_CONTRACT.properties?.verified_at?.pattern, PROTOCOL_INSTANT_SOURCE);
  const receipt = Bundle.linkValid().json("verification_receipt.json");
  const got: Record<string, string[]> = {};
  const expected: Record<string, string[]> = {};
  for (const [label, value] of Object.entries({ ...NOT_INSTANTS, "leap-day": LEAP_DAY })) {
    got[label] = receiptContractErrors({ ...receipt, verified_at: value });
    expected[label] = label === "leap-day" ? [] : ["$.verified_at:calendar"];
  }
  assert.deepEqual(got, expected);
});

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a receipt instant that is not a date fails the run at the structure check and the link at the link check`, () => {
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const [label, value] of Object.entries({ ...NOT_INSTANTS, "leap-day": LEAP_DAY })) {
      const b = Bundle.linkValid();
      b.edit("verification_receipt.json", (r) => { r.verified_at = value; });
      b.seal();
      got[label] = {
        structureRun: outcome(verify(b), ["registry_link"]),
        linkRun: outcome(verify(b, { registryEntry: linkEntryFor(b) }), ["registry_link"]),
      };
      expected[label] = label === "leap-day"
        ? { structureRun: { ...PASS, registry_link: null }, linkRun: { ...PASS, registry_link: true } }
        : { structureRun: { ...FAIL, registry_link: null }, linkRun: { ...FAIL, registry_link: false } };
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: a registry-entry or trust-registry instant that is not a date fails its document`, () => {
    const b = Bundle.linkValid().seal();
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const [label, value] of Object.entries(NOT_INSTANTS)) {
      for (const field of ["issued_at", "effective_at", "anchored_at"]) {
        const authRun = ephemeralAuthorizationWith(b, { entry: (e) => { e[field] = value; } });
        got[`entry.${field}.${label}`] = {
          linkRun: outcome(verify(b, { registryEntry: authRun.registryEntry }), ["registry_link"]),
          authRun: outcome(verify(b, authRun), CHECKS),
        };
        expected[`entry.${field}.${label}`] = {
          linkRun: { ...FAIL, registry_link: false },
          authRun: { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" },
        };
      }
      const trustChanges: Record<string, (t: any) => void> = {
        issued_at: (t) => { t.issued_at = value; },
        effective_at: (t) => { t.effective_at = value; },
        expires_at: (t) => { t.expires_at = value; },
        "entries[0].effective_from": (t) => { t.entries[0].effective_from = value; },
        "entries[0].expires_at": (t) => { t.entries[0].expires_at = value; },
        // on a second, revoked entry under another key: the authorized key is active and may not
        // carry a revoked_at, and its point under a second entry would be ambiguous (row 6)
        "entries[1].revoked_at": (t) => {
          t.entries.push({ ...t.entries[0], issuer_id: "issuer_other_demo", issuer_key_id: "other-key-1", public_key_hex: SMALL_Y_POINT, status: "revoked", revoked_at: value });
        },
      };
      for (const [where, change] of Object.entries(trustChanges)) {
        got[`trust.${where}.${label}`] = outcome(verify(b, ephemeralAuthorizationWith(b, { trust: change })), CHECKS);
        expected[`trust.${where}.${label}`] = { ...FAIL, registry_link: true, trust_registry: false, registry_signature: "UNSUPPORTED" };
      }
    }
    const leap = ephemeralAuthorizationWith(b, {
      entry: (e) => { e.anchored_at = LEAP_DAY; },
      trust: (t) => {
        t.entries.push({ ...t.entries[0], issuer_id: "issuer_other_demo", issuer_key_id: "other-key-1", public_key_hex: SMALL_Y_POINT, status: "revoked", revoked_at: LEAP_DAY });
      },
    });
    got["leap-day"] = outcome(verify(b, leap), CHECKS);
    expected["leap-day"] = { ...REVIEW, registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" };
    assert.deepEqual(got, expected);
  });
}
