// The registry-entry signature step of the authorization check: its order and its labels, as in
// the Python verifier.
//
// The step is trust-registry-authorization.md section 6, rows 14 to 20, in the order trust-root.md
// section 5 gives a root signature, so one signature is judged one way wherever it appears:
//   1. no signature object: MALFORMED_SIGNATURE, the first finding after authorization;
//   2. the signing payload (not v2), then the pair of algorithm and key type, from the verifier's
//      own allowlist: UNSUPPORTED_SIGNING_PAYLOAD, UNSUPPORTED_SIGNATURE_ALGORITHM;
//   3. the form of the value, 128 lowercase hex characters: MALFORMED_SIGNATURE;
//   4. the key ids, compared with the authorized key id: SIGNATURE_KEY_MISMATCH;
//   5. SIGNATURE_INVALID for whatever is well formed and does not verify, including a public key
//      that is not an uncompressed point on the curve.
//
// In a bundle verification an earlier step refuses some of them: a signature without payload_id
// and payload_version breaks the entry's contract (no earlier payload is defined), and a
// well-formed later payload fires the version gate (UNSUPPORTED_VERSION). The order rows call the
// helper, because the entry contract refuses a malformed signature value before a bundle
// verification reaches the step.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, REVIEW, ephemeralAuthorizationWith as material, outcome } from "./bundle-kit.ts";

/** Authorization material at the operator's evaluation time, which the fixture windows hold. */
const ephemeralAuthorizationWith = (...args: Parameters<typeof material>) => ({ ...material(...args), evaluationTime: "2026-05-10T00:00:00Z" });
import { verifyRegistryEntrySignature } from "../src/signature.ts";

const CHECKS = ["registry_link", "trust_registry", "registry_signature"];
const failed = (label: string) => ({ ...FAIL, registry_link: true, trust_registry: false, registry_signature: label });
const refusedEntry = { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" };

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: signature step labels in an authorization run`, () => {
    const b = Bundle.linkValid().seal();
    const rows: Record<string, [ReturnType<typeof ephemeralAuthorizationWith>, Record<string, unknown>]> = {
      control: [ephemeralAuthorizationWith(b), { ...REVIEW, registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" }],
      "signature-null": [ephemeralAuthorizationWith(b, { entry: (e) => { e.signature = null; } }), failed("MALFORMED_SIGNATURE")],
      "signature-absent": [ephemeralAuthorizationWith(b, { entry: (e) => { delete e.signature; } }), failed("MALFORMED_SIGNATURE")],
      "public-key-off-curve": [
        ephemeralAuthorizationWith(b, { trust: (t) => { t.entries[0].public_key_hex = `04${"11".repeat(64)}`; } }),
        failed("SIGNATURE_INVALID"),
      ],
      "public-key-not-a-point-encoding": [
        ephemeralAuthorizationWith(b, { trust: (t) => { t.entries[0].public_key_hex = "ab".repeat(32); } }),
        failed("SIGNATURE_INVALID"),
      ],
      "no-payload-members": [
        ephemeralAuthorizationWith(b, { entry: (e) => { delete e.signature.payload_id; delete e.signature.payload_version; } }),
        refusedEntry,
      ],
      "no-payload-members-and-key-id-mismatch": [
        ephemeralAuthorizationWith(b, {
          entry: (e) => { delete e.signature.payload_id; delete e.signature.payload_version; e.signature.key_id = "other-key"; },
        }),
        refusedEntry,
      ],
      "algorithm-outside-the-allowlist": [
        ephemeralAuthorizationWith(b, { entry: (e) => { e.signature.algorithm = "ed25519"; } }),
        failed("UNSUPPORTED_SIGNATURE_ALGORITHM"),
      ],
      "key-type-outside-the-allowlist": [
        ephemeralAuthorizationWith(b, { trust: (t) => { t.entries[0].key_type = "ed25519"; } }),
        failed("UNSUPPORTED_SIGNATURE_ALGORITHM"),
      ],
      "algorithm-out-of-grammar": [
        ephemeralAuthorizationWith(b, { entry: (e) => { e.signature.algorithm = "ED25519"; } }),
        refusedEntry,
      ],
      "signature-key-id-mismatch": [
        ephemeralAuthorizationWith(b, { entry: (e) => { e.signature.key_id = "other-key"; } }),
        failed("SIGNATURE_KEY_MISMATCH"),
      ],
    };
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const [label, [authRun, want]] of Object.entries(rows)) {
      got[label] = outcome(verify(b, authRun), CHECKS);
      expected[label] = { ...want };
    }
    assert.deepEqual(got, expected);
    // A well-formed later signing payload stops the run at its version gate.
    const later = verify(b, ephemeralAuthorizationWith(b, { entry: (e) => { e.signature.payload_id = "registry_entry_signing_payload_v3"; e.signature.payload_version = 3; } }));
    assert.deepEqual([later.status, later.exit_code, later.errors.map(({ code, object, version }) => ({ code, object, version }))],
      ["UNSUPPORTED_VERSION", 4, [{ code: "unsupported_version", object: "signing_payload", version: "registry_entry_signing_payload_v3/3" }]]);
  });
}

test("the signature step checks payload, algorithm and form before the key ids", () => {
  const b = Bundle.linkValid().seal();
  const base = ephemeralAuthorizationWith(b);
  const publicKey: string = base.trustRegistry.entries[0].public_key_hex;
  const step = (change?: (e: any) => void, key = publicKey, keyType = "secp256k1") => {
    const entry = JSON.parse(JSON.stringify(base.registryEntry));
    change?.(entry);
    return verifyRegistryEntrySignature(entry, key, { expectedKeyId: "demo-key-2", keyType }).status;
  };
  const mismatch = (e: any) => { e.signature.key_id = "other-key"; };
  const got = {
    valid: step(),
    "value-missing": step((e) => { delete e.signature.signature; }),
    "value-missing-and-key-id-mismatch": step((e) => { delete e.signature.signature; mismatch(e); }),
    "value-uppercase-and-key-id-mismatch": step((e) => { e.signature.signature = e.signature.signature.toUpperCase(); mismatch(e); }),
    "value-not-a-string": step((e) => { e.signature.signature = 7; }),
    "signature-an-array": step((e) => { e.signature = []; }),
    "algorithm-and-form-and-key-id": step((e) => { e.signature.algorithm = "ed25519"; e.signature.signature = "z".repeat(128); mismatch(e); }),
    "payload-and-algorithm": step((e) => { e.signature.payload_version = 3; e.signature.algorithm = "ed25519"; }),
    "no-payload-and-algorithm": step((e) => { delete e.signature.payload_id; delete e.signature.payload_version; e.signature.algorithm = "ed25519"; }),
    "key-type-and-form": step((e) => { e.signature.signature = "z".repeat(128); }, publicKey, "ed25519"),
    "unknown-key-type": step(undefined, publicKey, "unknown_alg"),
    "entry-issuer-key-id-mismatch": step((e) => { e.issuer_key_id = "other-key"; }),
    "public-key-off-curve": step(undefined, `04${"11".repeat(64)}`),
    "public-key-not-uncompressed-hex": step(undefined, `04${"zz".repeat(64)}`),
    "public-key-uppercase": step(undefined, `04${publicKey.slice(2).toUpperCase()}`),
  };
  assert.deepEqual(got, {
    valid: "VALID_SIGNATURE",
    "value-missing": "MALFORMED_SIGNATURE",
    "value-missing-and-key-id-mismatch": "MALFORMED_SIGNATURE",
    "value-uppercase-and-key-id-mismatch": "MALFORMED_SIGNATURE",
    "value-not-a-string": "MALFORMED_SIGNATURE",
    "signature-an-array": "MALFORMED_SIGNATURE",
    "algorithm-and-form-and-key-id": "UNSUPPORTED_SIGNATURE_ALGORITHM",
    "payload-and-algorithm": "UNSUPPORTED_SIGNING_PAYLOAD",
    "no-payload-and-algorithm": "UNSUPPORTED_SIGNING_PAYLOAD",
    "key-type-and-form": "UNSUPPORTED_SIGNATURE_ALGORITHM",
    "unknown-key-type": "UNSUPPORTED_SIGNATURE_ALGORITHM",
    "entry-issuer-key-id-mismatch": "SIGNATURE_KEY_MISMATCH",
    "public-key-off-curve": "SIGNATURE_INVALID",
    "public-key-not-uncompressed-hex": "SIGNATURE_INVALID",
    "public-key-uppercase": "SIGNATURE_INVALID",
  });
});
