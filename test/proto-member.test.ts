// A JSON member named __proto__, through the three entries (filesystem, in-memory map, browser
// build). Objects built from untrusted keys are filled by definition, never by assignment:
// `o["__proto__"] = v` sets the prototype of `o` instead of creating a member, so the member would
// vanish from every digest: a projection naming it would fail where Python passes, and a receipt
// or manifest that gained one would still match the digest committed before it was added.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, jcsText, linkEntryFor, outcome, sha256Hex } from "./bundle-kit.ts";

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a projected canonical-input member named __proto__ is hashed and passes`, () => {
    const b = Bundle.linkValid();
    b.setBytes("canonical_input.json", jcsText(b.json("canonical_input.json")).slice(0, -1) + ',"__proto__":{"hidden":"A"}}');
    b.edit("p1.json", (p) => {
      p.ik = [...p.ik, "__proto__"];
      p.ih = b.inputHashFor(p);
    });
    const report = verify(b.seal());
    assert.deepEqual(outcome(report, ["p1_input_hash"]), { ...PASS, p1_input_hash: true });
  });

  test(`${entryName}: a canonical input carrying __proto__ with no ik is hashed whole and passes`, () => {
    const b = Bundle.linkValid();
    const text = jcsText(b.json("canonical_input.json")).slice(0, -1) + ',"__proto__":{"hidden":"A"}}';
    b.setBytes("canonical_input.json", text);
    b.edit("p1.json", (p) => {
      delete p.ik;
      p.ih = `sha256:${sha256Hex(jcsText(JSON.parse(text)))}`;
    });
    const report = verify(b.seal());
    assert.deepEqual(outcome(report, ["p1_input_hash"]), { ...PASS, p1_input_hash: true });
  });

  test(`${entryName}: a receipt that gains a __proto__ member does not match the committed receipt hash`, () => {
    const b = Bundle.linkValid().seal();
    const entry = linkEntryFor(b);
    b.setBytes("verification_receipt.json", jcsText(b.json("verification_receipt.json")).slice(0, -1) + ',"__proto__":{"status":"pass"}}');
    const report = verify(b, { registryEntry: entry });
    assert.deepEqual(outcome(report, ["registry_link"]), { ...FAIL, registry_link: false });
  });

  test(`${entryName}: a manifest that declares a member named __proto__ does not match its sidecar`, () => {
    const b = Bundle.linkValid().seal();
    const entry = linkEntryFor(b);
    b.setBytes("__proto__", "smuggled");
    const manifest = jcsText(b.json("manifest.json"));
    b.setBytes("manifest.json", manifest.replace('"files":{', `"files":{"__proto__":"${sha256Hex("smuggled")}",`));
    const report = verify(b, { registryEntry: entry });
    assert.deepEqual(outcome(report, ["manifest_sha256", "registry_link"]), { ...FAIL, manifest_sha256: false, registry_link: false });
  });
}
