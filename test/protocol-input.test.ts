import assert from "node:assert/strict";
import test from "node:test";

import { parseRegistryEntry, parseTrustRegistry } from "../src/protocol-input.js";

const entry = {
  object_type: "registry_entry", schema_version: "v1",
  registry_entry_id: "reg_registry_entry_demo", receipt_id: "vr_receipt_demo",
  issuer_id: "issuer_demo", issuer_key_id: "key_demo", asset_type: "property",
  workflow: "property_review", subject_ref_hash: `sha256:${"1".repeat(64)}`,
  manifest_hash: `sha256:${"2".repeat(64)}`, receipt_hash: `sha256:${"3".repeat(64)}`,
  policy_id: "policy.demo", policy_version: "1.0.0",
  reason_code_catalog_version: "loquitur.reason_codes.v1", verdict: "PASS",
  reason_codes: ["INTEGRITY_OK"], issued_at: "2026-07-20T00:00:00Z",
  privacy_classification: "public_commitment", disclosure_profile: "minimal_public",
};

const trust = {
  object_type: "trust_registry", schema_version: "v1", trust_registry_id: "tr_trust_demo",
  registry_operator_id: "operator_demo", registry_version: "1.0.0",
  issued_at: "2026-07-20T00:00:00Z", effective_at: "2026-07-20T00:00:00Z",
  expires_at: "2027-07-20T00:00:00Z",
  entries: [{
    issuer_id: "issuer_demo", issuer_display_name: "Demo", issuer_key_id: "key_demo",
    key_type: "secp256k1", public_key_hex: "04" + "1".repeat(128), status: "active",
    effective_from: "2026-07-20T00:00:00Z", expires_at: "2027-07-20T00:00:00Z",
    allowed_asset_types: ["property"], allowed_workflows: ["property_review"],
  }],
  signature: { algorithm: "secp256k1_ecdsa_sha256", key_id: "root", signature: "demo" },
};

test("valid wire inputs become validated types only after parsing", () => {
  assert.equal(parseRegistryEntry(entry).ok, true);
  assert.equal(parseTrustRegistry(trust).ok, true);
});

test("extra fields and missing required fields fail closed", () => {
  const extra = parseRegistryEntry({ ...entry, secret_side_channel: "forbidden" });
  assert.equal(extra.ok, false);
  if (!extra.ok) assert.ok(extra.errors.some((error) => error.includes("unexpected field")));
  const missing = { ...entry };
  delete (missing as Record<string, unknown>).receipt_id;
  assert.equal(parseRegistryEntry(missing).ok, false);
});

test("an unknown verdict fails closed; a key type is an identifier the allowlist judges later", () => {
  assert.equal(parseRegistryEntry({ ...entry, verdict: "MAYBE" }).ok, false);
  // A well-formed key type the verifier does not support satisfies the contract: the signature
  // step answers it with UNSUPPORTED_SIGNATURE_ALGORITHM. One outside the grammar does not.
  const keyType = (value: unknown) => {
    const changed = structuredClone(trust);
    changed.entries[0]!.key_type = value as string;
    return parseTrustRegistry(changed).ok;
  };
  assert.deepEqual([keyType("ed25519"), keyType("unknown_alg"), keyType("Ed25519"), keyType(""), keyType("_x"), keyType(7)],
    [true, true, false, false, false, false]);
});
