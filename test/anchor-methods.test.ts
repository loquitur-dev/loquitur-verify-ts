// One signed registry entry has one H, with no anchor and under an anchor of each method.
//
// anchor-commitment.md section 1 binds whatever the anchoring method, and the anchor is outside the
// signing payload (signing-envelope-v2.md section 1). The corpus vector vectors/anchor-methods.json
// carries one signed entry with `anchor` null and with an anchor of each registered method
// (anchor-commitment.md section 6); this checks, with this package's own signing message and
// secp256k1 code, that every case has the declared digest and that its one signature verifies.
// Each root skips, saying why, when LOQUITUR_CORPUS_ROOTS names no corpus root or the root carries
// no such vector.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { registryEntrySigningPayloadHash, verifyRegistryEntrySignature } from "../src/signature.ts";

const ROOTS = (process.env.LOQUITUR_CORPUS_ROOTS ?? "")
  .split(delimiter)
  .map((part) => part.trim())
  .filter((part) => part.length > 0);
const VECTOR = join("vectors", "anchor-methods.json");

test("the corpus roots are named", { skip: ROOTS.length === 0 ? "LOQUITUR_CORPUS_ROOTS names no corpus root" : false }, () => {
  assert.ok(ROOTS.length > 0);
});

for (const root of ROOTS) {
  const path = join(root, VECTOR);
  test(`every anchor method under ${root} keeps the signing message and the signature`,
    { skip: existsSync(path) ? false : `${root} carries no ${VECTOR}` }, () => {
      const vector = JSON.parse(readFileSync(path, "utf8"));
      const methods = new Set<string | null>();
      const signatures = new Set<string>();
      for (const item of vector.cases) {
        const entry = item.entry as Record<string, any>;
        methods.add(entry.anchor === null || entry.anchor === undefined ? null : entry.anchor.method);
        assert.equal(registryEntrySigningPayloadHash(entry), vector.signing_payload_sha256, item.id);
        signatures.add(entry.signature.signature);
        const verified = verifyRegistryEntrySignature(entry, vector.public_key_hex, { expectedKeyId: entry.issuer_key_id, keyType: "secp256k1" });
        assert.deepEqual([verified.valid, verified.status], [true, "VALID_SIGNATURE"], item.id);
      }
      assert.deepEqual(methods, new Set([null, "blockchain_transaction", "rfc3161_timestamp", "transparency_log_checkpoint"]));
      assert.equal(signatures.size, 1);
    });
}
