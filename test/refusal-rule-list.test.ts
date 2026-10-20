// Each bundle layer has one list of refusal rules (report-contract.md section 5.3). A layer that
// read every member and the verification row judged over the members the host did read, when it
// failed to read another, apply the same list: a refusal is reported with the same words on both
// paths. A second copy of a rule on the read-row path could drift from the layer's and judge one
// bundle two ways; this test reads each refusal both ways and requires one answer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle } from "./bundle-kit.ts";
import { BundleReadError } from "../src/verify.ts";
import { verifyBundleFiles, type BundleReader, type VerifyReport } from "../src/verify-core.ts";

/** A reader with no listing over `bundle`; it fails to read `failing`, when named, with a BundleReadError. */
function reader(bundle: Bundle, failing: string | null): BundleReader {
  const read = (name: string): Uint8Array | null => {
    if (name === failing) throw new BundleReadError(`the host cannot read ${name}`);
    return bundle.has(name) ? bundle.bytes(name) : null;
  };
  return { readBytes: read, readText: (name) => { const b = read(name); return b === null ? null : new TextDecoder().decode(b); } };
}

function message(report: VerifyReport, code: string): string | undefined {
  return report.errors.find((e) => e.code === code)?.message;
}

const notStrict = (bundle: Bundle, name: string): Bundle => bundle.setBytes(name, '{"s": ');
function p1BreakingItsContract(): Bundle {
  const bundle = Bundle.linkValid();
  bundle.edit("p1.json", (p1) => { p1.unexpected = 1; });
  return bundle.seal();
}
function p1NotAnObject(): Bundle {
  return Bundle.linkValid().seal().setBytes("p1.json", "[1]");
}

// name -> [bundle, the member the host fails to read on the second path, the refusal's code, its
// words]
const CASES: Array<[string, () => Bundle, string, string, string]> = [
  ["a manifest that is not strict JSON", () => notStrict(Bundle.linkValid().seal(), "manifest.json"), "manifest.sha256",
    "manifest_verification_failed", "manifest.json is not a strict JSON object"],
  ["a manifest without its sidecar", () => Bundle.linkValid().seal().delete("manifest.sha256"), "manifest.json",
    "manifest_verification_failed", "manifest.sha256 is not a regular member"],
  ["a P1 that breaks its contract", p1BreakingItsContract, "canonical_input.json",
    "p1_verification_failed", "p1.json breaks its closed contract"],
  ["a P1 that is not an object", p1NotAnObject, "p1.sha256",
    "p1_verification_failed", "p1.json is not a strict JSON object"],
  ["a canonical input that is not strict JSON", () => notStrict(Bundle.linkValid(), "canonical_input.json").seal(), "p1.sha256",
    "p1_verification_failed", "canonical_input.json is present and is not a strict JSON object"],
  ["an envelope that is not strict JSON", () => notStrict(Bundle.linkValid().seal(), "envelope_env1.json"), "envelope.sha256",
    "envelope_verification_failed", "the envelope is not a strict JSON object"],
];

for (const [name, make, failing, code, words] of CASES) {
  test(`one refusal rule on both paths: ${name}`, () => {
    const whole = verifyBundleFiles(reader(make(), null));
    const partial = verifyBundleFiles(reader(make(), failing));
    // The second path is the read-row path: the host failed to read a member of the same layer.
    const readRow = code.replace("_verification_failed", "_read_failed");
    assert.equal(message(whole, readRow), undefined, `${name}: every member read`);
    assert.ok(message(partial, readRow) !== undefined, `${name}: the host failed to read ${failing}`);
    assert.equal(message(whole, code), words, `${name}: the layer that read every member`);
    assert.equal(message(partial, code), words, `${name}: the row judged over the members read`);
  });
}
