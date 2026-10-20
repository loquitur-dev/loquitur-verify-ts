// A compact signature whose r or s is out of range is a signature that does not verify:
// SIGNATURE_INVALID, as in the Python verifier.
//
// MALFORMED_SIGNATURE is a matter of form (trust-registry-authorization.md section 6, row 18: not
// 128 lowercase hex characters). A value of that form whose r or s is 0, equal to the curve order n
// or above it is well formed and does not verify (row 21, SIGNATURE_INVALID). @noble/curves throws
// on such a scalar, and the catch around the verification reports the throw as SIGNATURE_INVALID,
// as it does a high s, which the library returns false for.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, REVIEW, ephemeralAuthorizationWith, outcome } from "./bundle-kit.ts";
import { verifyRegistryEntrySignature } from "../src/signature.ts";

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const hex64 = (value: bigint) => value.toString(16).padStart(64, "0");
const CHECKS = ["registry_link", "trust_registry", "registry_signature"];

const SCALARS: Record<string, (s: string) => string> = {
  "r-equal-to-n": (s) => hex64(N) + s.slice(64),
  "r-above-n": (s) => hex64(N + 5n) + s.slice(64),
  "r-all-f": (s) => "f".repeat(64) + s.slice(64),
  "r-zero": (s) => "0".repeat(64) + s.slice(64),
  "s-zero": (s) => s.slice(0, 64) + "0".repeat(64),
  "s-equal-to-n": (s) => s.slice(0, 64) + hex64(N),
  "s-above-n": (s) => s.slice(0, 64) + hex64(N + 7n),
  "s-high": (s) => s.slice(0, 64) + hex64(N - BigInt(`0x${s.slice(64)}`)),
};

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: r or s out of range is SIGNATURE_INVALID, not MALFORMED_SIGNATURE`, () => {
    const b = Bundle.linkValid().seal();
    const got: Record<string, unknown> = { control: outcome(verify(b, ephemeralAuthorizationWith(b)), CHECKS) };
    const expected: Record<string, unknown> = {
      control: { ...REVIEW, registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" },
    };
    for (const [label, change] of Object.entries(SCALARS)) {
      const authRun = ephemeralAuthorizationWith(b, { afterSigning: (e) => { e.signature.signature = change(e.signature.signature); } });
      got[label] = outcome(verify(b, authRun), CHECKS);
      expected[label] = { ...FAIL, registry_link: true, trust_registry: false, registry_signature: "SIGNATURE_INVALID" };
    }
    assert.deepEqual(got, expected);
  });
}

test("verifyRegistryEntrySignature reports r or s out of range as SIGNATURE_INVALID", () => {
  const b = Bundle.linkValid().seal();
  const got: Record<string, unknown> = {};
  const expected: Record<string, unknown> = {};
  for (const [label, change] of Object.entries(SCALARS)) {
    const authRun = ephemeralAuthorizationWith(b, { afterSigning: (e) => { e.signature.signature = change(e.signature.signature); } });
    const result = verifyRegistryEntrySignature(authRun.registryEntry, authRun.trustRegistry.entries[0].public_key_hex, {
      expectedKeyId: authRun.trustRegistry.entries[0].issuer_key_id,
      keyType: authRun.trustRegistry.entries[0].key_type,
    });
    got[label] = { valid: result.valid, status: result.status };
    expected[label] = { valid: false, status: "SIGNATURE_INVALID" };
  }
  assert.deepEqual(got, expected);
});
