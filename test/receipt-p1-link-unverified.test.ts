// registry-link.md section 3: receipt_p1_sha256 holds when the receipt names no P1, or names the
// digest of the P1 that verified (bundle-objects.md section 4). A P1 whose sidecar disagrees did
// not verify, so a receipt naming the digest recomputed from its bytes does not hold the link: the
// operand on the bundle side is unevaluated, and an unevaluated operand never satisfies a hard
// comparison. The receipt's manifest digest is checked on its own beside it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, linkEntryFor, outcome } from "./bundle-kit.ts";

/** The sealed link bundle whose receipt names its P1, changed as given before the entry is bound. */
function withReceiptNamingP1(change: (b: Bundle) => void = () => {}) {
  const bundle = Bundle.linkValid();
  bundle.edit("verification_receipt.json", (r) => { r.p1_sha256 = "sha256:" + "0".repeat(64); });
  bundle.seal();
  change(bundle);
  return { bundle, entry: linkEntryFor(bundle) };
}

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a receipt naming the verified P1 holds the link`, () => {
    const { bundle, entry } = withReceiptNamingP1();
    assert.equal(bundle.json("verification_receipt.json").p1_sha256, `sha256:${bundle.p1Digest()}`);
    assert.deepEqual(outcome(verify(bundle, { registryEntry: entry }), ["registry_link"]), { ...PASS, registry_link: true });
  });

  test(`${entryName}: a receipt naming a P1 that failed its sidecar does not hold the link`, () => {
    const { bundle, entry } = withReceiptNamingP1((b) => {
      // P1 changes after sealing; the manifest's file digests and the receipt follow the new bytes,
      // but p1.sha256 keeps the old digest, so P1 fails its sidecar and is not verified.
      const staleSidecar = new TextDecoder().decode(b.bytes("p1.sha256"));
      b.edit("p1.json", (p) => { p.ih = "sha256:" + "1".repeat(64); });
      b.seal({ p1: false });
      assert.equal(new TextDecoder().decode(b.bytes("p1.sha256")), staleSidecar);
      assert.notEqual(staleSidecar, b.p1Digest());
      assert.equal(b.json("verification_receipt.json").p1_sha256, `sha256:${b.p1Digest()}`);
    });
    const report = verify(bundle, { registryEntry: entry });
    assert.deepEqual(outcome(report, ["registry_link"]), { ...FAIL, registry_link: false });
  });

  test(`${entryName}: a receipt manifest digest that differs alone fails the link`, () => {
    const { bundle, entry } = withReceiptNamingP1((b) => {
      b.edit("verification_receipt.json", (r) => { r.manifest_sha256 = "sha256:" + "2".repeat(64); });
    });
    assert.equal(entry.receipt_hash, `sha256:${bundle.receiptDigest()}`);
    assert.deepEqual(outcome(verify(bundle, { registryEntry: entry }), ["registry_link"]), { ...FAIL, registry_link: false });
  });
}
