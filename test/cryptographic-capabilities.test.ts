import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { VECTORS_DIR } from "./bundle-kit.ts";
import { SIGNATURE_ALGORITHM, verifyRegistryEntrySignature, type SignatureVerificationOptions } from "../src/signature.ts";
import {
  CRYPTOGRAPHIC_CAPABILITY_PROFILE,
  RESERVED_UNSUPPORTED_ALGORITHMS,
  SUPPORTED_SIGNATURE_ALGORITHMS,
  SUPPORTED_SIGNATURE_PAIRS,
  SUPPORTED_TRUST_KEY_TYPES,
  signatureAlgorithmSupported,
  trustKeyTypeSupported,
} from "../src/cryptographic-capabilities.ts";

test("release 0.1 capability matrix is closed", () => {
  assert.equal(CRYPTOGRAPHIC_CAPABILITY_PROFILE, "loquitur.crypto_capabilities.v0.1");
  assert.deepEqual(SUPPORTED_SIGNATURE_ALGORITHMS, ["secp256k1_ecdsa_sha256"]);
  assert.deepEqual(SUPPORTED_TRUST_KEY_TYPES, ["secp256k1"]);
  assert.deepEqual(RESERVED_UNSUPPORTED_ALGORITHMS, ["ed25519"]);
  assert.equal(signatureAlgorithmSupported("secp256k1_ecdsa_sha256"), true);
  assert.equal(trustKeyTypeSupported("secp256k1"), true);
  assert.equal(signatureAlgorithmSupported("ed25519"), false);
  assert.equal(trustKeyTypeSupported("ed25519"), false);
});

// The signature step dispatches on one algorithm: the allowlist of pairs names only it, so a second
// algorithm can only come with its own verification, never through a guard. Every pair outside the
// allowlist is UNSUPPORTED_SIGNATURE_ALGORITHM, with and without the key type the trust registry
// names, before the signature is read.
test("the allowlist of pairs names the one algorithm the signature step verifies", () => {
  assert.deepEqual(SUPPORTED_SIGNATURE_PAIRS.map(([algorithm]) => algorithm), [SIGNATURE_ALGORITHM]);
  const entry = JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_registry_entry.json"), "utf8"));
  const withAlgorithm = (algorithm: unknown) => ({ ...entry, signature: { ...entry.signature, algorithm } });
  // A well-formed key the step never reaches for the refused pairs.
  const key = `04${"11".repeat(64)}`;
  for (const algorithm of ["ed25519", "secp256k1_ecdsa_sha512", "SECP256K1_ECDSA_SHA256", 7, null]) {
    // Without a key type, as a caller that omits it would call: no pair holds without one.
    const noKeyType = { expectedKeyId: entry.issuer_key_id } as unknown as SignatureVerificationOptions;
    for (const options of [noKeyType, { expectedKeyId: entry.issuer_key_id, keyType: "secp256k1" }, { expectedKeyId: entry.issuer_key_id, keyType: "ed25519" }]) {
      assert.equal(verifyRegistryEntrySignature(withAlgorithm(algorithm), key, options).status, "UNSUPPORTED_SIGNATURE_ALGORITHM", `${String(algorithm)} ${JSON.stringify(options)}`);
    }
  }
  assert.equal(verifyRegistryEntrySignature(withAlgorithm(SIGNATURE_ALGORITHM), key, { expectedKeyId: entry.issuer_key_id, keyType: "ed25519" }).status, "UNSUPPORTED_SIGNATURE_ALGORITHM");
  assert.notEqual(verifyRegistryEntrySignature(withAlgorithm(SIGNATURE_ALGORITHM), key, { expectedKeyId: entry.issuer_key_id, keyType: "secp256k1" }).status, "UNSUPPORTED_SIGNATURE_ALGORITHM");
});
