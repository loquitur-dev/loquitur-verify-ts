// A registry entry whose signature.signature is not exactly 128 lowercase hex characters breaks the
// entry's closed contract (registry_entry.schema.json: ^[a-f0-9]{128}$), at the link check and at
// the authorization check alike: lowercase only, nothing trimmed or case-folded.
//
// The check belongs to the entry's contract, not to the signature step: at the link check, where no
// signature is evaluated, an uppercase or 'z'-filled signature would otherwise link and pass, while
// the Python verifier refuses the entry (registry_entry_contract_violation). The contract failure
// comes first on both sides: registry_link false, trust_registry null, and the signature never
// evaluated (UNSUPPORTED).
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, ephemeralAuthorization, outcome } from "./bundle-kit.ts";

const CHECKS = ["registry_link", "trust_registry", "registry_signature"];

const FORMS: Record<string, (s: string) => string> = {
  uppercase: (s) => s.toUpperCase(),
  oneUppercaseCharacter: (s) => {
    const i = s.search(/[a-f]/);
    return s.slice(0, i) + s[i]!.toUpperCase() + s.slice(i + 1);
  },
  z128: () => "z".repeat(128),
  short127: (s) => s.slice(0, 127),
  long130: (s) => `${s}ab`,
  leadingSpace: (s) => ` ${s.slice(1)}`,
  trailingNewline: (s) => `${s}\n`,
  fullwidthDigit: (s) => `\uff10${s.slice(1)}`,
};

function signedWith(form: (s: string) => string) {
  const b = Bundle.linkValid().seal();
  const authRun = ephemeralAuthorization(b);
  const entry = authRun.registryEntry as { signature: { signature: string } };
  entry.signature.signature = form(entry.signature.signature);
  return { b, authRun };
}

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a registry entry signature that is not 128 lowercase hex characters fails the entry contract at the link and authorization checks`, () => {
    const got: Record<string, unknown> = {};
    for (const [label, form] of Object.entries({ valid: (s: string) => s, ...FORMS })) {
      const { b, authRun } = signedWith(form);
      got[label] = {
        linkRun: outcome(verify(b, { registryEntry: authRun.registryEntry }), CHECKS),
        authRun: outcome(verify(b, authRun), CHECKS),
      };
    }
    const refused = {
      linkRun: { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" },
      authRun: { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" },
    };
    const expected: Record<string, unknown> = {
      // The control: the same entry, correctly signed, links at the link check and is trusted at
      // the authorization check (REVIEW: no root pins the trust registry, trust-root.md section 6).
      valid: {
        linkRun: { ...PASS, registry_link: true, trust_registry: null, registry_signature: "UNSUPPORTED" },
        authRun: { ...REVIEW, registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" },
      },
    };
    for (const label of Object.keys(FORMS)) expected[label] = refused;
    assert.deepEqual(got, expected);
  });
}
