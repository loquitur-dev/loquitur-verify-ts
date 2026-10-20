// The version gates of document-contracts.md section 1 ("Version gate") and report-contract.md
// section 5.5: every versioned object is read for its version identifier before its contract. A
// well-formed identifier other than the supported one stops the run with the single error
// unsupported_version, naming the object and the identifier as read, status UNSUPPORTED_VERSION,
// verdict null, exit 4; anything that is not well formed is left to the object's contract.
//
// One run per gate, through every entry of this package, beside the run the same documents give at
// the supported version, so a gate that never fired could not pass here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, ephemeralAuthorizationWith, ephemeralRoot, linkEntryFor, rootDocument } from "./bundle-kit.ts";
import type { VerifyReport } from "../src/verify-core.ts";

type Doc = Record<string, any>;
const EVALUATION_TIME = "2026-05-10T00:00:00Z";

/** Authorization material over a sealed bundle: entry, trust registry signed by a root, the root document. */
function material(changes: { bundle?: (b: Bundle) => void; entry?: (e: Doc) => void; trust?: (t: Doc) => void; roots?: (d: Doc) => void } = {}) {
  const bundle = Bundle.linkValid();
  changes.bundle?.(bundle);
  bundle.seal();
  const { root, sign } = ephemeralRoot("root-1");
  const m = ephemeralAuthorizationWith(bundle, { entry: changes.entry, trust: (t: Doc) => { delete t.signature; } });
  changes.trust?.(m.trustRegistry);
  sign(m.trustRegistry);
  const trustRoots = rootDocument([root]);
  changes.roots?.(trustRoots);
  return { bundle, options: { registryEntry: m.registryEntry, trustRegistry: m.trustRegistry, trustRoots, evaluationTime: EVALUATION_TIME } };
}

const gate = (report: VerifyReport) => ({
  status: report.status,
  verdict: report.verdict,
  exit_code: report.exit_code,
  reason: report.outcome.reason,
  errors: report.errors.map(({ code, object, version }: any) => ({ code, object, version })),
  checks_established: report.checks_established,
  review_reasons: report.review_reasons,
  trust_registry: report.trust_registry,
});

const fired = (object: string, version: string) => ({
  status: "UNSUPPORTED_VERSION", verdict: null, exit_code: 4, reason: "unsupported_version",
  errors: [{ code: "unsupported_version", object, version }], checks_established: [], review_reasons: [], trust_registry: null,
});

// The changes that make each gate fire, in the gate order of the table.
const GATES: Array<[string, string, string, Parameters<typeof material>[0]]> = [
  ["trust-root document", "trust_root_document", "v2", { roots: (d) => { d.schema_version = "v2"; } }],
  ["manifest", "manifest", "loquitur.bundle.v2", { bundle: (b) => { b.edit("manifest.json", (m) => { m.schema_version = "loquitur.bundle.v2"; }); } }],
  ["receipt", "verification_receipt", "v3", { bundle: (b) => { b.edit("verification_receipt.json", (r) => { r.schema_version = "v3"; }); } }],
  ["receipt vocabulary", "reason_code_vocabulary", "loquitur.reason_codes.v2",
    { bundle: (b) => { b.edit("verification_receipt.json", (r) => { r.reason_code_vocabulary_version = "loquitur.reason_codes.v2"; }); } }],
  ["registry entry", "registry_entry", "v2", { entry: (e) => { e.schema_version = "v2"; } }],
  ["entry vocabulary", "reason_code_vocabulary", "loquitur.reason_codes.v2", { entry: (e) => { e.reason_code_catalog_version = "loquitur.reason_codes.v2"; } }],
  ["signing payload", "signing_payload", "registry_entry_signing_payload_v3/3",
    { entry: (e) => { e.signature.payload_id = "registry_entry_signing_payload_v3"; e.signature.payload_version = 3; } }],
  ["trust registry", "trust_registry", "v2", { trust: (t) => { t.schema_version = "v2"; } }],
];

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: each version gate fires on a well-formed later version, and names the object and the version`, () => {
    const control = material();
    assert.deepEqual([verify(control.bundle, control.options).status], ["OFFLINE_OK"], "the documents at the supported versions verify");
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const [label, object, version, changes] of GATES) {
      const { bundle, options } = material(changes);
      got[label] = gate(verify(bundle, options));
      expected[label] = fired(object, version);
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: the first gate that fires stops the run, before any evidence outcome`, () => {
    // A tampered bundle beside a later entry: the gate decides, not the tampering
    // (report-contract.md section 3.1).
    const tampered = material({ entry: (e) => { e.schema_version = "v2"; } });
    tampered.bundle.setBytes("canonical_input.json", '{"tampered":true}');
    assert.deepEqual(gate(verify(tampered.bundle, tampered.options)), fired("registry_entry", "v2"));
    // Two gates at once: the earlier of the table decides.
    const both = material({
      bundle: (b) => { b.edit("manifest.json", (m) => { m.schema_version = "loquitur.bundle.v7"; }); },
      trust: (t) => { t.schema_version = "v9"; },
      roots: (d) => { d.schema_version = "v3"; },
    });
    assert.deepEqual(gate(verify(both.bundle, both.options)), fired("trust_root_document", "v3"));
    const later = material({
      bundle: (b) => { b.edit("manifest.json", (m) => { m.schema_version = "loquitur.bundle.v7"; }); },
      entry: (e) => { e.schema_version = "v4"; },
    });
    assert.deepEqual(gate(verify(later.bundle, later.options)), fired("manifest", "loquitur.bundle.v7"));
  });

  test(`${entryName}: an identifier that is not well formed is the object's contract, not a gate`, () => {
    const cases: Array<[string, Parameters<typeof material>[0], string]> = [
      ["manifest bundle-v1", { bundle: (b) => { b.edit("manifest.json", (m) => { m.schema_version = "bundle-v1"; }); } }, "OFFLINE_FAIL"],
      ["manifest loquitur.bundle.v0", { bundle: (b) => { b.edit("manifest.json", (m) => { m.schema_version = "loquitur.bundle.v0"; }); } }, "OFFLINE_FAIL"],
      ["receipt V3", { bundle: (b) => { b.edit("verification_receipt.json", (r) => { r.schema_version = "V3"; }); } }, "OFFLINE_FAIL"],
      ["entry V2", { entry: (e) => { e.schema_version = "V2"; } }, "OFFLINE_FAIL"],
      ["entry 2", { entry: (e) => { e.schema_version = 2; } }, "OFFLINE_FAIL"],
      ["trust registry v01", { trust: (t) => { t.schema_version = "v01"; } }, "OFFLINE_FAIL"],
      ["signing payload v2 / 2.0, the integer 2", { entry: (e) => { e.signature.payload_version = 2.0; } }, "OFFLINE_OK"],
      ["signing payload without either member", { entry: (e) => { delete e.signature.payload_id; delete e.signature.payload_version; } }, "OFFLINE_FAIL"],
      ["signing payload version 1000000000", { entry: (e) => { e.signature.payload_version = 1000000000; } }, "OFFLINE_FAIL"],
    ];
    for (const [label, changes, status] of cases) {
      const { bundle, options } = material(changes);
      const report = verify(bundle, options);
      assert.deepEqual([report.status, report.errors.some((e) => e.code === "unsupported_version")], [status, false], label);
    }
  });
}

test("a trust-root document of a later version is a report, not a refusal; a malformed one is refused", () => {
  const { bundle, options } = material({ roots: (d) => { d.schema_version = "v2"; } });
  const [, verify] = ENTRIES[1]!;
  assert.deepEqual(gate(verify(bundle, options)), fired("trust_root_document", "v2"));
  const malformed = material({ roots: (d) => { d.schema_version = "2"; } });
  assert.throws(() => verify(malformed.bundle, malformed.options), (err: Error) => err.name === "TrustRootError");
  // The gate is read at invocation, before any evidence: beside a bundle alone too.
  assert.deepEqual(gate(verify(bundle, { trustRoots: options.trustRoots })), fired("trust_root_document", "v2"));
});

test("an entry gate fires only in a run that reads the entry", () => {
  const { bundle, options } = material({ entry: (e) => { e.schema_version = "v2"; } });
  const [, verify] = ENTRIES[1]!;
  // Beside an input refused as a whole, nothing is read: the refusal is the only error.
  const empty = new Bundle();
  const report = verify(empty, { registryEntry: options.registryEntry });
  assert.deepEqual(report.errors.map((e) => e.code), ["bundle_root_invalid"]);
  assert.equal(verify(bundle, { registryEntry: linkEntryFor(bundle, { schema_version: "v2" }) }).status, "UNSUPPORTED_VERSION");
});
