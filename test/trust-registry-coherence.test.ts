// A trust registry whose revocation fields or validity windows contradict each other is malformed,
// as in the Python verifier: trust_registry false, whatever the key's status says.
//
// Key status does not decide alone (trust-registry-authorization.md section 3): a key marked
// active with a revoked_at, or a registry issued after its own expiry, is malformed. Refused, in
// any entry of the registry:
//   - status active with a non-null revoked_at or revocation_reason;
//   - status suspended with a non-null revoked_at or revocation_reason;
//   - status revoked with a null revoked_at;
//   - effective_from later than expires_at;
// and for the registry itself: effective_at, or issued_at, later than expires_at.
// A registry issued before it takes effect, equal bounds, and a revoked key carrying revoked_at are
// well formed. The evaluation time is the fixture entry's effective_at, 2026-05-10T00:00:00Z.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, REVIEW, ephemeralAuthorizationWith, outcome } from "./bundle-kit.ts";

const CHECKS = ["registry_link", "trust_registry", "registry_signature"];
const INSTANT = "2026-05-10T00:00:00Z";
const REFUSED = { ...FAIL, registry_link: true, trust_registry: false, registry_signature: "UNSUPPORTED" };
const AUTHORIZED = { ...REVIEW, registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" };

const key = (fields: Record<string, unknown>) => (t: any) => { Object.assign(t.entries[0], fields); };
const secondIssuer = (fields: Record<string, unknown>) => (t: any) => {
  t.entries.push({ ...t.entries[0], issuer_id: "issuer_other_demo", issuer_key_id: "other-key-1", ...fields });
};

const ROWS: Record<string, [((t: any) => void) | undefined, Record<string, unknown>]> = {
  "active-with-revoked_at-in-the-past": [key({ revoked_at: "2026-05-01T00:00:00Z" }), REFUSED],
  "active-with-revoked_at-in-the-future": [key({ revoked_at: "2026-06-01T00:00:00Z" }), REFUSED],
  "active-with-revocation_reason-only": [key({ revocation_reason: "key_compromise" }), REFUSED],
  "revoked-with-revoked_at-null": [key({ status: "revoked" }), REFUSED],
  "suspended-with-revoked_at": [key({ status: "suspended", revoked_at: "2026-05-01T00:00:00Z" }), REFUSED],
  "suspended-with-revocation_reason-only": [key({ status: "suspended", revocation_reason: "under_review" }), REFUSED],
  "other-issuer-entry-suspended-with-revoked_at": [secondIssuer({ status: "suspended", revoked_at: "2026-05-01T00:00:00Z" }), REFUSED],
  "key-effective_from-after-expires_at": [key({ effective_from: "2026-05-20T00:00:00Z", expires_at: "2026-05-01T00:00:00Z" }), REFUSED],
  "registry-effective_at-after-expires_at": [(t) => { t.effective_at = "2026-05-20T00:00:00Z"; t.expires_at = "2026-05-01T00:00:00Z"; }, REFUSED],
  "registry-issued_at-after-expires_at": [(t) => { t.issued_at = "2026-12-01T00:00:00Z"; }, REFUSED],
  "other-issuer-entry-active-with-revoked_at": [secondIssuer({ revoked_at: "2026-05-01T00:00:00Z" }), REFUSED],
  "other-issuer-entry-window-inverted": [secondIssuer({ effective_from: "2026-05-20T00:00:00Z", expires_at: "2026-05-01T00:00:00Z" }), REFUSED],
  control: [undefined, AUTHORIZED],
  "revoked-with-revoked_at": [key({ status: "revoked", revoked_at: "2026-05-01T00:00:00Z" }), REFUSED],
  "suspended-with-revoked_at-null": [key({ status: "suspended" }), REFUSED],
  "key-window-a-single-instant": [key({ effective_from: INSTANT, expires_at: INSTANT }), AUTHORIZED],
  "registry-issued-before-it-takes-effect": [(t) => { t.issued_at = "2026-04-01T00:00:00Z"; }, AUTHORIZED],
  "registry-issued_at-equal-to-expires_at": [(t) => { t.issued_at = "2026-05-29T12:00:00Z"; }, AUTHORIZED],
  "registry-effective_at-equal-to-expires_at": [(t) => { t.effective_at = INSTANT; t.expires_at = INSTANT; t.issued_at = INSTANT; }, AUTHORIZED],
};

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: contradictory revocation fields and windows make the trust registry malformed`, () => {
    const b = Bundle.linkValid().seal();
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const [label, [change, want]] of Object.entries(ROWS)) {
      got[label] = outcome(verify(b, ephemeralAuthorizationWith(b, { trust: change })), CHECKS);
      expected[label] = { ...want };
    }
    assert.deepEqual(got, expected);
  });
}
