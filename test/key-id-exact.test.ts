// Authorization key ids are compared exactly as written, as the Python verifier compares them.
//
// The trust entry is looked up with the entry's issuer_key_id as written, and the signature step
// compares the authorized key id, the signature's key_id and the entry's issuer_key_id as written
// too. Trimming any of them would make the two verifiers disagree on the same bytes: a
// trust-registry key id with a trailing space or no-break space, carried identically by the entry
// and its signature, is authorized by both, and a signature key_id that differs from the
// authorized key only by whitespace is refused by both. Nothing is trimmed anywhere; the
// whitespace set W decides only whether a value is empty.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, REVIEW, ephemeralAuthorizationWith, outcome } from "./bundle-kit.ts";

const CHECKS = ["registry_link", "trust_registry", "registry_signature"];
const AUTHORIZED = { ...REVIEW, registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" };
const KEY_NOT_FOUND = { ...FAIL, registry_link: true, trust_registry: false, registry_signature: "UNSUPPORTED" };
const KEY_MISMATCH = { ...FAIL, registry_link: true, trust_registry: false, registry_signature: "SIGNATURE_KEY_MISMATCH" };
// A signature key_id made only of W is not a key id the signature step compares: the entry breaks
// its contract (registry-link.md section 2, the entry's free strings) and no registry is evaluated.
const ENTRY_REFUSED = { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" };

// [entry issuer_key_id, signature key_id, trust-registry issuer_key_id] -> outcome
const ROWS: Record<string, [[string, string, string], Record<string, unknown>]> = {
  control: [["demo-key-2", "demo-key-2", "demo-key-2"], AUTHORIZED],
  "entry-leading-space": [[" demo-key-2", " demo-key-2", "demo-key-2"], KEY_NOT_FOUND],
  "entry-leading-space-signature-plain": [[" demo-key-2", "demo-key-2", "demo-key-2"], KEY_NOT_FOUND],
  "entry-trailing-tab": [["demo-key-2\t", "demo-key-2\t", "demo-key-2"], KEY_NOT_FOUND],
  "registry-trailing-space-used-identically": [["demo-key-2 ", "demo-key-2 ", "demo-key-2 "], AUTHORIZED],
  "registry-trailing-nbsp-used-identically": [["demo-key-2\u00a0", "demo-key-2\u00a0", "demo-key-2\u00a0"], AUTHORIZED],
  "signature-trailing-space-only": [["demo-key-2", "demo-key-2 ", "demo-key-2"], KEY_MISMATCH],
  "signature-leading-ideographic-space-only": [["demo-key-2", "\u3000demo-key-2", "demo-key-2"], KEY_MISMATCH],
  "signature-key-id-only-whitespace": [["demo-key-2", "\u3000", "demo-key-2"], ENTRY_REFUSED],
};

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: issuer and signature key ids are matched as written`, () => {
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    const b = Bundle.linkValid().seal();
    for (const [label, [[entryKeyId, signatureKeyId, registryKeyId], want]] of Object.entries(ROWS)) {
      const authRun = ephemeralAuthorizationWith(b, {
        entry: (e) => { e.issuer_key_id = entryKeyId; e.signature.key_id = signatureKeyId; },
        trust: (t) => { t.entries[0].issuer_key_id = registryKeyId; },
      });
      got[label] = outcome(verify(b, authRun), CHECKS);
      expected[label] = { ...want };
    }
    assert.deepEqual(got, expected);
  });
}
