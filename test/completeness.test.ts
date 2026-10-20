// Completeness (bundle-objects.md section 1): a file under the bundle root that the manifest does
// not declare, other than manifest.json, manifest.sha256, envelope_env1.json, envelope.sha256 and
// verification_receipt.json, makes the run REVIEW; empty directories are not members; a reader that
// cannot list its members is capped at REVIEW, because it cannot show nothing is undeclared.
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { rmSync, writeFileSync } from "node:fs";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, outcome, tempDir, verifyWithByteReader } from "./bundle-kit.ts";
import { bundleReaderFromMap, verifyBundleFiles } from "../src/verify-core.ts";
import { verifyBundle } from "../src/verify.ts";

const CHECKS = ["manifest_files"];

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: an undeclared file makes the run REVIEW; the structural names and empty directories do not`, () => {
    const extraRoot = Bundle.linkValid().seal().setBytes("extra.txt", "undeclared\n");
    const extraSub = Bundle.linkValid().seal().setBytes("sub/extra.txt", "undeclared\n");
    const emptyDir = Bundle.linkValid().seal();
    emptyDir.dirs.push("empty");
    // envelope.json is not an envelope name: alone beside envelope.sha256 it leaves the envelope
    // incomplete (envelope_incomplete), and it is an undeclared member.
    const legacyEnvelope = Bundle.linkValid().seal();
    legacyEnvelope.setBytes("envelope.json", legacyEnvelope.bytes("envelope_env1.json")).delete("envelope_env1.json");
    const got = {
      extraRoot: outcome(verify(extraRoot), CHECKS),
      extraSub: outcome(verify(extraSub), CHECKS),
      emptyDir: outcome(verify(emptyDir), CHECKS),
      legacyEnvelope: outcome(verify(legacyEnvelope), CHECKS),
      fixture: outcome(verify(Bundle.linkValid().seal()), CHECKS),
    };
    assert.deepEqual(got, {
      extraRoot: { ...REVIEW, manifest_files: true },
      extraSub: { ...REVIEW, manifest_files: true },
      emptyDir: { ...PASS, manifest_files: true },
      legacyEnvelope: { ...FAIL, manifest_files: true },
      fixture: { ...PASS, manifest_files: true },
    });
  });
}

test("a reader that cannot list its members is capped at REVIEW; a directory argument is the bundle root", () => {
  const b = Bundle.linkValid().seal();
  const map: Record<string, string> = {};
  for (const [name, data] of b.files) map[name] = new TextDecoder().decode(data);
  const listing = bundleReaderFromMap(map);
  assert.deepEqual(outcome(verifyBundleFiles(listing)), PASS);
  assert.deepEqual(outcome(verifyWithByteReader(b)), REVIEW);
  assert.deepEqual(outcome(verifyBundleFiles({ ...listing, listMembers: () => null })), REVIEW);
  // A failure still dominates the cap.
  const broken = Bundle.linkValid().seal().setBytes("manifest.sha256", "0".repeat(64));
  assert.deepEqual(outcome(verifyWithByteReader(broken)), FAIL);

  // verifyBundle does not look for a bundle below the directory it is given (bundle-objects.md
  // section 1), with or without a file beside the bundle.
  const dir = tempDir("wrapper");
  try {
    Bundle.linkValid().seal().writeTo(join(dir, "input", "bundle"));
    assert.deepEqual(outcome(verifyBundle(join(dir, "input"))), FAIL);
    Bundle.linkValid().seal().writeTo(join(dir, "input2", "bundle"));
    writeFileSync(join(dir, "input2", "peer.txt"), "peer\n");
    assert.deepEqual(outcome(verifyBundle(join(dir, "input2"))), FAIL);
    // The bundle inside, verified as its own root, passes: the file beside it is not in it.
    assert.deepEqual(outcome(verifyBundle(join(dir, "input2", "bundle"))), PASS);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
