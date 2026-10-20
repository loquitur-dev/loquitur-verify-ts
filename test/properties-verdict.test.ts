// Properties of the verdict, with a small budget since each example is a whole verification run
// through verifyBundleFiles over the map reader, every member given as bytes:
//
// - the link fixture bundle passes, and with any one byte of any declared member changed it
//   never passes;
// - a trust registry handed over with no trust root never passes, whatever the evaluation time,
//   whether or not a root signed it, and whatever its signature member holds.
//
// The issuer and root keys are made in memory for the run and never written or printed.
// Seed, budget and generators: test/property-kit.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { Bundle, ephemeralAuthorizationWith, ephemeralRoot } from "./bundle-kit.ts";
import { bundleReaderFromMap, verifyBundleFiles, type VerifyOptions, type VerifyReport } from "../src/verify-core.ts";
import { check, jsonValue } from "./property-kit.ts";

/** Verify `files` through the map reader, every member as a copy of its bytes. */
function verifyMap(files: Map<string, Uint8Array>, opts: VerifyOptions = {}): VerifyReport {
  const map: Record<string, Uint8Array> = {};
  for (const [name, bytes] of files) {
    Object.defineProperty(map, name, { value: Uint8Array.from(bytes), enumerable: true, writable: true, configurable: true });
  }
  return verifyBundleFiles(bundleReaderFromMap(map), opts);
}

const bundle = Bundle.linkValid().seal();
const declared = Object.keys(bundle.json("manifest.json").files as Record<string, string>).filter((name) => bundle.has(name));

test("changing any byte of a declared member never yields PASS", () => {
  assert.equal(verifyMap(bundle.files).verdict, "PASS", "the unchanged bundle passes");
  assert.ok(declared.length >= 3, `only ${declared.length} declared members`);
  check(
    fc.property(fc.constantFrom(...declared), fc.nat(), fc.integer({ min: 1, max: 255 }), (name, at, delta) => {
      const files = new Map(bundle.files);
      const bytes = Uint8Array.from(files.get(name)!);
      fc.pre(bytes.length > 0);
      const i = at % bytes.length;
      bytes[i] = bytes[i]! ^ delta;
      files.set(name, bytes);
      const report = verifyMap(files);
      assert.notEqual(report.verdict, "PASS", `${name} byte ${i} ^ ${delta}`);
    }),
    200,
    0.1,
  );
});

test("a trust registry supplied with no trust root never yields PASS", () => {
  const { registryEntry, trustRegistry } = ephemeralAuthorizationWith(bundle, { trust: (t) => { delete t.signature; } });
  const { root, sign } = ephemeralRoot("root-1");
  const signed = sign(structuredClone(trustRegistry));
  // The same run with the root supplied passes: the property below is not vacuous.
  const held = verifyMap(bundle.files, {
    registryEntry: structuredClone(registryEntry),
    trustRegistry: structuredClone(signed),
    trustRoots: { object_type: "trust_root_document", schema_version: "v1", roots: [root] },
    evaluationTime: "2026-05-10T00:00:00Z",
  });
  assert.equal(held.verdict, "PASS");

  const instant = fc
    .record({ y: fc.integer({ min: 2025, max: 2027 }), m: fc.integer({ min: 1, max: 12 }), d: fc.integer({ min: 1, max: 28 }), h: fc.integer({ min: 0, max: 23 }) })
    .map(({ y, m, d, h }) => `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}T${String(h).padStart(2, "0")}:00:00Z`);
  const signature = fc.oneof(
    fc.constant("root-signed"),
    fc.constant("absent"),
    jsonValue.map((value) => ({ value })),
  );
  check(
    fc.property(fc.oneof(fc.constant("2026-05-10T00:00:00Z"), instant), signature, (evaluationTime, sig) => {
      const registry: Record<string, unknown> = structuredClone(sig === "root-signed" ? signed : trustRegistry);
      if (typeof sig === "object") registry.signature = sig.value;
      const report = verifyMap(bundle.files, { registryEntry: structuredClone(registryEntry), trustRegistry: registry, evaluationTime });
      assert.notEqual(report.verdict, "PASS", `${evaluationTime} ${JSON.stringify(sig)}`);
    }),
    200,
    0.1,
  );
});
