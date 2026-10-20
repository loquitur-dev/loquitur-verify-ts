// registry_entry.schema.json and trust_registry.schema.json give every instant the pattern
// ^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)Z$,
// and the Python verifier holds both documents to their closed schemas; so does this one, not
// merely to four, two, two, two, two and two digits. A registry entry whose issued_at, effective_at
// or anchored_at has month 00 or 13, day 00 or 32, hour 24, minute 60 or second 61 is refused
// (registry_entry_contract_violation) before any link or trust conclusion, at the link and
// authorization checks. A trust registry with such an issued_at, or such a revoked_at in an entry,
// is refused.
//
// An instant that matches the pattern but is not a date (February 30, second 60) is refused too, as
// a calendar violation of the same contract: test/protocol-instants-calendar.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, SMALL_Y_POINT, ephemeralAuthorization, outcome } from "./bundle-kit.ts";

const CHECKS = ["registry_link", "trust_registry", "registry_signature"];

const OUTSIDE_PATTERN: Record<string, string> = {
  month00: "2026-00-29T12:00:00Z",
  month13: "2026-13-29T12:00:00Z",
  day00: "2026-04-00T12:00:00Z",
  day32: "2026-04-32T12:00:00Z",
  hour24: "2026-04-29T24:00:00Z",
  minute60: "2026-04-29T12:60:00Z",
  second61: "2026-04-29T12:00:61Z",
};

const ENTRY_FIELDS = ["issued_at", "effective_at", "anchored_at"];
const TRUST_FIELDS = ["issued_at", "effective_at", "expires_at"];
const TRUST_ENTRY_FIELDS = ["effective_from", "expires_at"];

// revoked_at is carried by a second, revoked entry for another issuer. The authorized key stays
// active, and an active key may not carry a revoked_at (a contradictory trust registry is
// malformed), so on the key itself the instant could not be told apart from the contradiction. The
// second entry carries another key: the authorized key's point under it would be ambiguous (row 6).
function revokedSecondEntry(trust: { entries: Array<Record<string, unknown>> }, revokedAt: string): void {
  trust.entries.push({ ...trust.entries[0], issuer_id: "issuer_other_demo", issuer_key_id: "other-key-1", public_key_hex: SMALL_Y_POINT, status: "revoked", revoked_at: revokedAt });
}

const ENTRY_REFUSED = { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" };
const TRUST_REFUSED = { ...FAIL, registry_link: true, trust_registry: false, registry_signature: "UNSUPPORTED" };
const LINKED = { ...PASS, registry_link: true, trust_registry: null, registry_signature: "UNSUPPORTED" };
const TRUSTED = { ...REVIEW, registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" };

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: registry-entry and trust-registry instants outside the schema pattern fail their contract`, () => {
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    const b = Bundle.linkValid().seal();
    const control = ephemeralAuthorization(b);
    got["control"] = { linkRun: outcome(verify(b, { registryEntry: control.registryEntry }), CHECKS), authRun: outcome(verify(b, control), CHECKS) };
    expected["control"] = { linkRun: LINKED, authRun: TRUSTED };

    for (const [label, value] of Object.entries(OUTSIDE_PATTERN)) {
      for (const field of ENTRY_FIELDS) {
        const authRun = ephemeralAuthorization(b, { [field]: value });
        got[`entry.${field}.${label}`] = {
          linkRun: outcome(verify(b, { registryEntry: authRun.registryEntry }), CHECKS),
          authRun: outcome(verify(b, authRun), CHECKS),
        };
        expected[`entry.${field}.${label}`] = { linkRun: ENTRY_REFUSED, authRun: ENTRY_REFUSED };
      }
      for (const field of TRUST_FIELDS) {
        const authRun = ephemeralAuthorization(b);
        (authRun.trustRegistry as Record<string, unknown>)[field] = value;
        got[`trust.${field}.${label}`] = outcome(verify(b, authRun), CHECKS);
        expected[`trust.${field}.${label}`] = TRUST_REFUSED;
      }
      for (const field of TRUST_ENTRY_FIELDS) {
        const authRun = ephemeralAuthorization(b);
        (authRun.trustRegistry as { entries: Array<Record<string, unknown>> }).entries[0]![field] = value;
        got[`trust.entries[0].${field}.${label}`] = outcome(verify(b, authRun), CHECKS);
        expected[`trust.entries[0].${field}.${label}`] = TRUST_REFUSED;
      }
      const revoked = ephemeralAuthorization(b);
      revokedSecondEntry(revoked.trustRegistry as { entries: Array<Record<string, unknown>> }, value);
      got[`trust.entries[1].revoked_at.${label}`] = outcome(verify(b, revoked), CHECKS);
      expected[`trust.entries[1].revoked_at.${label}`] = TRUST_REFUSED;
    }

    // Inside the pattern, at its edges: unchanged. 2025, not 2026: a trust registry issued after
    // its own expiry (2026-05-29) is malformed.
    for (const value of ["2026-01-01T00:00:00Z", "2025-12-31T23:59:59Z"]) {
      for (const field of ["issued_at", "anchored_at"]) {
        const authRun = ephemeralAuthorization(b, { [field]: value });
        got[`entry.${field}.${value}`] = outcome(verify(b, { registryEntry: authRun.registryEntry }), CHECKS);
        expected[`entry.${field}.${value}`] = LINKED;
      }
      for (const [where, set] of [
        ["trust.issued_at", (t: Record<string, unknown>) => { t.issued_at = value; }],
        ["trust.entries[1].revoked_at", (t: { entries: Array<Record<string, unknown>> }) => { revokedSecondEntry(t, value); }],
      ] as const) {
        const authRun = ephemeralAuthorization(b);
        (set as (t: unknown) => void)(authRun.trustRegistry);
        got[`${where}.${value}`] = outcome(verify(b, authRun), CHECKS);
        expected[`${where}.${value}`] = TRUSTED;
      }
    }
    assert.deepEqual(got, expected);
  });
}
