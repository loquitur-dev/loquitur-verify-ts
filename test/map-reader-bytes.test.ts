// bundleReaderFromMap takes each member as a string or as its bytes. Given bytes, the in-memory
// and browser entries see what the Node reader sees: a member that is not UTF-8 text hashes as it
// is, and invalid UTF-8 in a JSON member or a sidecar is refused, not repaired. A host holding
// bytes need not decode them first, and a byte value is never read as "[object Uint8Array]".
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Bundle, FAIL, PASS, jcsText, outcome, sha256Hex, verifyInBrowserBuildBytes, verifyInMemoryBytes, verifyOnDisk,
} from "./bundle-kit.ts";

const utf8 = new TextEncoder();
const BINARY = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0xff, 0x00, 0xc3, 0x28, 0x80, 0xfe]);

function withBinaryMember(): Bundle {
  const b = Bundle.linkValid();
  b.setBytes("scan.bin", BINARY);
  b.edit("manifest.json", (m) => { m.files["scan.bin"] = ""; });
  return b.seal();
}

function replaceFirst(b: Bundle, name: string, text: string, bytes: number[]): Bundle {
  const data = b.bytes(name);
  const needle = utf8.encode(text);
  for (let i = 0; i + needle.length <= data.length; i++) {
    if (needle.every((v, j) => data[i + j] === v)) {
      return b.setBytes(name, new Uint8Array([...data.slice(0, i), ...bytes, ...data.slice(i + needle.length)]));
    }
  }
  throw new Error(`${text} not in ${name}`);
}

const ROWS: Array<[string, () => Bundle, Record<string, unknown>]> = [
  ["every member given as bytes", () => Bundle.linkValid().seal(), { ...PASS, manifest_files: true, p1_input_hash: true }],
  ["a declared binary member", withBinaryMember, { ...PASS, manifest_files: true }],
  ["invalid UTF-8 in manifest.json", () => {
    const b = Bundle.linkValid();
    b.edit("manifest.json", (m) => { m.schema_version = "manifest.fixture.v1\uFFFD"; });
    return replaceFirst(b.seal(), "manifest.json", "\uFFFD", [0xff]);
  }, { ...FAIL, manifest_sha256: false, manifest_files: false, envelope_links: false }],
  ["invalid UTF-8 in canonical_input.json", () => replaceFirst(Bundle.linkValid().seal(), "canonical_input.json", "001", [0x30, 0xc3, 0x28])
    .seal({ p1: false }), { ...FAIL, canonical_input_present: true, p1_input_hash: false }],
  ["invalid UTF-8 in the envelope", () => {
    const b = Bundle.linkValid().seal();
    b.edit("envelope_env1.json", (v) => { v.asset_id = "asset\uFFFD"; });
    b.setBytes("envelope.sha256", sha256Hex(jcsText(b.json("envelope_env1.json"))));
    return replaceFirst(b, "envelope_env1.json", "\uFFFD", [0xff]);
  }, { ...FAIL, envelope_present: true, envelope_sha256: false, envelope_links: false }],
  ["an invalid byte after manifest.sha256", () => {
    const b = Bundle.linkValid().seal();
    return b.setBytes("manifest.sha256", new Uint8Array([...b.bytes("manifest.sha256"), 0xff]));
  }, { ...FAIL, manifest_sha256: false }],
];

for (const [entryName, verify] of [["map", verifyInMemoryBytes], ["browser", verifyInBrowserBuildBytes]] as const) {
  test(`${entryName}: a map of Uint8Array values verifies as the filesystem reader does`, () => {
    const got: Record<string, unknown> = {};
    const want: Record<string, unknown> = {};
    for (const [label, build, expected] of ROWS) {
      const checks = Object.keys(expected).filter((k) => !["status", "verdict", "exit_code"].includes(k));
      want[label] = expected;
      // The filesystem reader is the reference for each row: the map must agree with it.
      assert.deepEqual(outcome(verifyOnDisk(build()), checks), expected, `fs: ${label}`);
      try {
        got[label] = outcome(verify(build()), checks);
      } catch (err) {
        got[label] = `threw ${(err as Error).name}: ${(err as Error).message}`;
      }
    }
    assert.deepEqual(got, want);
  });
}
