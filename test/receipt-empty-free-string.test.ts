// registry-link.md section 2: asset_id, network, anchor_provider and anchor_type, when they are
// strings, each have a code point outside the whitespace set W. The empty string has none, so a
// receipt carrying "" in any of them breaks its contract, as one carrying " " does.
import { test } from "node:test";
import assert from "node:assert/strict";
import { receiptContractErrors } from "../src/receipt-contract.ts";

const RECEIPT = {
  anchor_provider: null, anchor_type: null, asset_id: null, asset_type: "property",
  bundle_id: "bundle_demo_0001", manifest_sha256: "sha256:" + "c".repeat(64), network: null,
  object_type: "verification_receipt", p1_sha256: null, policy_id: "example.v1", policy_pack_sha256: null,
  policy_version: 1, primary_anchor: null, reason_code_vocabulary_version: "loquitur.reason_codes.v1",
  reason_codes: ["INTEGRITY_OK"], schema_version: "v2", status: "pass",
  verification_mode: "offline", verified_at: "2026-05-01T12:00:00Z",
};

test("the receipt fixture of this file satisfies the contract", () => {
  assert.deepEqual(receiptContractErrors(RECEIPT), []);
});

for (const member of ["asset_id", "network", "anchor_provider", "anchor_type"]) {
  test(`an empty ${member} breaks the receipt's contract, as a blank one does`, () => {
    for (const value of ["", " ", "\u00a0\u3000"]) {
      const errors = receiptContractErrors({ ...RECEIPT, [member]: value });
      assert.ok(errors.length > 0, JSON.stringify(value));
    }
    assert.deepEqual(receiptContractErrors({ ...RECEIPT, [member]: "x" }), []);
  });
}
